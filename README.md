<h1>Casable</h1>
<p>
This project will be the Casable Project to enable NodeJS express applications to authenticate using CAS.
</p>

Useage:
<pre>
var cas = require('casable');
var auth = cas.authentication('http://cas.tw.com/cas', {logoutPath:'/unsecure'});

app.get('/securePage', auth, function(request, response) {
  var username = request.authenticatedUser.id
  response.send(username + "<br><a href='/logout'>Logout</a>");
});
</pre>

<p>Simply define a URL like this for logout functionality</p>
<pre>
app.get('/logout', auth, function(request, response) {
});
</pre>

<p>Make sure that these session and cookie routes are enabled</p>

<pre>
app.use(express.cookieParser());
app.use(express.session({secret: 'abcxyz'}));
</pre>

<h2>Todo</h2>
Make Casable work with HTTPS
