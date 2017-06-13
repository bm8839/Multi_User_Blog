import os
import re
import hmac
import random
import jinja2
import webapp2
import hashlib
from string import letters
from google.appengine.ext import db

# This secret is used in hashing the cookie
secret = "thisisreallychallenging"


# Setting the Environment. 'templates' is the name of the directory where all
# the html pages are stored.
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """ This function renders all the html pages using jinja."""
    t = jinja_env.get_template(template)
    return t.render(params)


def hash_cookie(s):
    """ String of digits (which is the key ID of the user from the Users
    table) comes into this function and it returns a very long secure 'hashed'
    string.
    """
    return hmac.new(secret, s).hexdigest()


def make_secure_cookie(s):
    """Takes in key ID of the user from the Users table as a string and returns
    a cookie made up of the key ID | secure hash of that ID.
    """
    return "%s|%s" % (s, hash_cookie(s))


def check_secure_cookie(h):
    """Verifies if a cookie is valid. Takes in the entire cookie, splits off
    key ID and the re-hashes that key ID to see if it generates the same
    cookie. If so, returns just the users key ID.
    """
    val = h.split('|')[0]
    if h == make_secure_cookie(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Contains many common functions used by many other classes to render
    web pages.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """Creates the cookie. Takes in the variable name for the cookie and
        the key ID of the user from the Users table. Makes the cookie and adds
        the cookie's name and value to the response header.
        """
        cookie_val = make_secure_cookie(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Takes in the variable name of the cookie and gets the value of that
        variable, checks it's validity and then returns the key ID string.
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_cookie(cookie_val)

    def login(self, user):
        """Begins the process of making a cookie. Here is where you give the
        cookie variable it's name. The Login class sends an entire User object
        from the Users table into this function and that object contains the
        key ID integer.
        """
        self.set_secure_cookie('user_cookie', str(user.key().id()))

    def logout(self):
        """Sets the value of the cookie variable name to NULL, in effect
        removing the user's cookie.
        """
        self.response.headers.add_header('Set-Cookie', 'user_cookie=; Path=/')

    def initialize(self, *a, **kw):
        """Overrides the __init__ but I'm not sure why. The next line of code
        reads the value of the user's cookie which should be the user's key ID.
        The last line takes that ID back to the User class and pulls the entire
        User object entity from the and assigns it to self.user.
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_cookie')
        self.user = uid and User.by_id(int(uid))


def make_salt():
    """Creates and returns a randomly generated 5 letter string."""
    return ''.join(random.choice(letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    """Takes in user's name, user's password, and user's salt (if it exists)
    and uses these 3 to generate a hashed secure password. Returns the hashed
    password and the salt used to create it.
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    """Takes in user's name, password, and hashed password tuple. The salt is
    split out and sent with the name and password and they go through the
    hash process again. If that result matches the hashed password tuple that
    was passed in then returns true.
    """
    salt = h.split(",")[1]
    if h == make_pw_hash(name, pw, salt):
        return True


# Parent to the User table
def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """Creates the User kind (table) in the datastore. Defines each piece of
    data (column) that will be entered into the table to make a whole entity
    (record) object.
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Takes in an integer which is the user's key ID and gets the user
        object that matches that ID from the User table and returns the whole
        object.
        """
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """Takes in the user's name, searches the User table and gets that
        whole user object and returns it.
        """
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """Takes in the user's name, password, email (if it exists) from the
        Signup class. Hashes the password and creates and returns all the data
        needed to put the object into the User table.
        """
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)


class Login(BlogHandler):
    """Handles the tasks needed for the user to login. It's called when the
    user clicks a link on the base.html page. Presents user with the
    login-form.html page.
    """
    def get(self):
        self.render('login-form.html')

    def post(self):
        """Takes the name and password submitted by the user and searches the
        User table. If found and the password is valid then logs in the user
        and presents them the Welcome page.
        """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.by_name(username)
        if u:
            v = valid_pw(username, password, u.pw_hash)
            if v:
                self.login(u)
                self.redirect('/blog/welcome')
            else:
                msg = 'Username found, but password incorrect'
                self.render('login-form.html', username=username, error=msg)
        else:
            msg = 'Username not found, do you need to SignUp?'
            self.render('login-form.html', error=msg)


# Functions to ensure username, password, and email conform to these rules.
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    """Handles tasks needed for a new user to signup/register. It's called when
    the user clicks a link on the base.html page. Presents the user with the
    signup-form.html page.
    """
    def get(self):
        self.render("signup-form.html")

    def post(self):
        """Takes each of the pieces of info input by the user and runs them
        through the validation functions above. If they fail, error messages
        are returned. If they pass, the User table is searched. If that name
        has not already been used, they are entered into the User table, logged
        in and sent to the Welcome page.
        """
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(username)
            if u:
                msg = 'That user already exists. Try a different username.'
                self.render('signup-form.html', error_username=msg)
            else:
                u = User.register(username, password, email)
                u.put()

                self.login(u)
                self.redirect('/blog/welcome')


class Welcome(BlogHandler):
    """Handles tasks to present the welcome.html page. If there is a self.user
    that means the user is logged in and has valid cookie. Refer to the
    BlogHandler class under the initialize function.
    """
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/blog/signup')


class Logout(BlogHandler):
    """Handles tasks to log the user out. It's called when the user clicks a
    link on the base.html page. It calls the logout function over in the
    BlogHandler class which removes the user's cookie.
    """
    def get(self):
        self.logout()
        self.redirect('/blog')


class EntireBlog(BlogHandler):
    """Handles task to pull all entities (records) from the Post table and the
    Comment table and sends them along with the blog.html page to be rendered
    so the user sees all the blog posts and their corresponding comments.
    """
    def get(self):
        posts = Post.all().order('-created')
        comments = Comment.all().order('-created')
        self.render('blog.html', posts=posts, comments=comments)


class EnterNewPost(BlogHandler):
    """Handles tasks needed for the user to create a new post."""
    def get(self):
        """If the user is logged in with a valid cookie, they are preented
        with the newpost.html page (input form). If not, the user is sent to
        the login page.
        """
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")

    def post(self):
        """When the submit button is clicked on the newpost.html page, the info
        on the form is sent here. Since subject and content are required fields
        for the Post table entry, their presence is checked. Then an entity is
        created in the Post table. The key ID from that specific entry is
        substituted into the url and sent to the ViewNewPost handler.
        """
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject,
                     content=content,
                     creator=self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


class ViewNewPost(BlogHandler):
    """Handles task of displaying the one lone post the user just created."""
    def get(self, post_id):
        """Pulls the string of the key ID from the url path that was sent in by
        the EnterNewPost handler and uses it to get the entire entity object
        that matches that key ID in the Post table. Then sends it over with the
        permalink.html page to be rendered.
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class EditPost(BlogHandler):
    """ This class handles editing posts. It's called when the user clicks a
    link on the post.html page. The get request generated by clicking the link
    sends the key ID of the post needing to be edited.
    """
    def get(self):
        """ If the user is logged in, this function takes the post ID from
        the get request, turns it from a string of digits into an integer,
        and calls the by_id function over in the Post class which returns that
        specific entire Post object. If the current user was the creator of
        the post, they are presented with the editpost.html page.
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if self.user.name == post.creator:
                self.render("editpost.html",
                            subject=post.subject,
                            content=post.content)
            else:
                error = "you can only EDIT your own posts"
                self.render('editpost.html', error=error)

        else:
            self.redirect("/blog/login")

    def post(self):
        """ When the user clicks the Submit button on the editpost.html page
        it comes back to this function with the ID of the post to be edited.
        If the user is logged in and was the creator of the post, and the
        subject and content is not blank, the post gets changed and put into
        the datastore and the user is redirected to the permalink.html page via
        the ViewNewPost class.
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            subject = self.request.get('subject')
            content = self.request.get('content')

            if self.user.name == post.creator:
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("editpost.html",
                                subject=post.subject,
                                content=post.content,
                                error=error)

        else:
            self.redirect('/blog/login')


class DeletePost(BlogHandler):
    """ This class handles deleting posts. It is called when the user clicks a
    link on the post.html page. The get request generated by clicking the link
    sends the key ID of the post needing to be deleted.
    """
    def get(self):
        """ If the user is logged in, this function takes the post ID from the
        from the get request, turns it from a string of digits into an integer,
        and calls the by_id function over in the Post class which returns that
        specific entire Post object. If the current user was the creator of
        the post, they are presented with the deletepost.html page.
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if self.user.name == post.creator:
                self.render("deletepost.html",
                            subject=post.subject,
                            content=post.content)
            else:
                error = "you can only DELETE your own posts"
                self.render("deletepost.html", error=error)
        else:
            self.redirect("/blog/login")

    def post(self):
        """ When the user clicks the DELETE button on the deletepost.html page
        it comes back to this function with the ID of the post to be deleted.
        If the user is logged in and was the creator of the post, the post
        gets deleted from the datastore.
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if self.user.name == post.creator:
                post.delete()

        self.redirect('/blog')


class LikePost(BlogHandler):
    """Handles tasks of entering user's names who "like" posts into the Post
    table and recording how many "likes" a post has gotten. When user clicks
    the "like" link on the post.html page, the request, which includes the key
    ID, comes to this handler.
    """
    def get(self):
        """If the user is logged in, the key ID is grabbed and sent over to the
        by_id function in the Post class. It brings back an entire object from
        the Post table. If the user is not the post's creator and if the user's
        name is not in the users_liked list of strings, the user's name is
        appended to the list and the number of likes goes up. Those two changes
        are updated for that object in the Post table.
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if ((self.user.name != post.creator) and
               (self.user.name not in post.users_liked)):
                post.users_liked.append(self.user.name)
                post.likes_qty += 1
                post.put()
                self.redirect("/blog")

            else:
                error = "you can't like your own post " \
                        "and you can only like a post one time"
                self.render("permalink.html", post=post, error=error)

        else:
            self.redirect("/blog/login")


# Parent to the Post table
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """Creates the Post kind (table) in the datastore. Defines each piece of
    data (column) that will be entered into the table to make a whole entity
    (record) object.
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    users_liked = db.StringListProperty(default=None)
    likes_qty = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, post_id):
        """Takes in the key ID and returns the entire object that has that
        key ID in the Post table.
        """
        return cls.get_by_id(post_id, parent=blog_key())

    def render(self):
        """This function is called from the permalink.html page or blog.html
        page. Takes in the entire Post object and preserves the whitespace in
        the content field by replacing newline characters with html line
        breaks. Then sends the entire Post entity (object) with the post.html
        to be rendered.
        """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# Parent to the Comment table
def comment_key(name='default'):
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    """Creates the Comment kind (table) in the datastore. Defines each piece of
    data (column) that will be entered into the table to make a whole entity
    (record) object.
    """
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, comment_id):
        """Takes in the key ID and returns the entire object that has that
        key ID in the Comment table.
        """
        return cls.get_by_id(comment_id, parent=comment_key())

    def render(self):
        """This function is called from the blog.html page. Takes in the entire
        Comment object and preserves the whitespace in the comment field by
        replacing newline characters with html line breaks. Then sends the
        entire Comment entity (object) with the postcomment.html page to be
        rendered.
        """
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("postcomment.html", c=self)


class MakeComment(BlogHandler):
    """Handles tasks needed for the user to create a comment. This handler is
    called when the user clicks the comment link on the post.html page. The get
    request generated by clicking the link sends the key ID of the post on
    which the comment will be made.
    """
    def get(self):
        """If user is logged in with a valid cookie, the post's key ID is
        grabbed from the request, sent over to the Post class where the by_id
        function returns the entire post record (object). The post's subject
        and content are rendered with the comment.html page (form).
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            self.render("comment.html",
                        subject=post.subject,
                        content=post.content)

        else:
            self.redirect("/blog/login")

    def post(self):
        """When the Submit button is clicked on the comment.html page, it comes
        to this function and the post's key ID and the comment are grabbed from
        the request. If they are both present, an entire object (record) is
        created (put) in the Comment kind (table).
        """
        if self.user:
            post_id = self.request.get('post_id')
            post_id = int(post_id)
            comment = self.request.get('comment')

            if comment and post_id:
                c = Comment(parent=comment_key(),
                            post_id=post_id,
                            comment=comment,
                            creator=self.user.name)
                c.put()
                self.redirect('/blog')
            else:
                self.redirect('/blog')

        else:
            self.redirect("/blog/login")


class EditComment(BlogHandler):
    """ This class handles editing comments. It's called when the user clicks a
    link on the postcomment.html page. The get request generated by clicking
    the link sends the key ID of the comment needing to be edited.
    """
    def get(self):
        """ If the user is logged in, this function takes the comment ID from
        the get request, turns it from a string of digits into an integer, and
        calls the by_id function over in the Comment class which returns that
        specific entire Comment object. If the current user was the creator of
        the comment, they are presented with the editcomment.html page.
        """
        if self.user:
            comment_id = self.request.get('comment_id')
            comment_id = int(comment_id)
            c = Comment.by_id(comment_id)

            if not c:
                self.error(404)
                return

            if self.user.name == c.creator:
                self.render("editcomment.html", comment=c.comment)
            else:
                error = "you can only EDIT your own comment"
                self.render('editcomment.html', error=error)

        else:
            self.redirect("/blog/login")

    def post(self):
        """ When the user clicks the Submit button on the editcomment.html page
        it comes back to this function with the ID of the comment to be edited.
        If the user is logged in and was the creator of the comment, and the
        comment is not blank, the comment gets changed and put into the
        datastore (Comment table).
        """
        if self.user:
            comment_id = self.request.get('comment_id')
            comment_id = int(comment_id)
            c = Comment.by_id(comment_id)
            newcomment = self.request.get('comment')

            if not c:
                self.error(404)
                return

            if self.user.name == c.creator:
                if newcomment:
                    c.comment = newcomment
                    c.put()
                    self.redirect('/blog')
                else:
                    error = "comment cannot be blank"
                    self.render("editcomment.html",
                                comment=c.comment,
                                error=error)

        else:
            self.redirect("/blog/login")


class DeleteComment(BlogHandler):
    """ This class handles deleting comments. It's called when the user clicks
    a link on the postcomment.html page. The get request generated by clicking
    the link sends the key ID of the comment needing to be deleted.
    """
    def get(self):
        """ If the user is logged in, this function takes the comment ID from
        the get request, turns it from a string of digits into an integer, and
        calls the by_id function over in the Comment class which returns that
        specific entire Comment object. If the current user was the creator of
        the comment, they are presented with the deletecomment.html page.
        """
        if self.user:
            comment_id = self.request.get('comment_id')
            comment_id = int(comment_id)
            c = Comment.by_id(comment_id)

            if not c:
                self.error(404)
                return

            if self.user.name == c.creator:
                self.render("deletecomment.html", comment=c.comment)
            else:
                error = "you can only DELETE your own comments"
                self.render('deletecomment.html', error=error)

        else:
            self.redirect("/blog/login")

    def post(self):
        """ When the user clicks the Submit button on the deletecomment.html
        page it comes back to this function with the ID of the comment to be
        deleted. If the user is logged in and was the creator of the comment,
        the comment gets deleted from the datastore (Comment table).
        """
        if self.user:
            comment_id = self.request.get('comment_id')
            comment_id = int(comment_id)
            c = Comment.by_id(comment_id)

            if not c:
                self.error(404)
                return

            if self.user.name == c.creator:
                c.delete()
                self.redirect('/blog')

        else:
            self.redirect("/blog/login")


app = webapp2.WSGIApplication([('/', EntireBlog),
                               ('/blog', EntireBlog),
                               ('/blog/login', Login),
                               ('/blog/welcome', Welcome),
                               ('/blog/signup', Signup),
                               ('/blog/newpost', EnterNewPost),
                               ('/blog/([0-9]+)', ViewNewPost),
                               ('/blog/editpost', EditPost),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/comment', MakeComment),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/like', LikePost),
                               ('/blog/logout', Logout)
                               ],
                              debug=True)
