Casable
===


This project will be the Casable Project to enable NodeJS express applications to authenticate using CAS.

**Make sure that these session and cookie routes are enabled**
```javascript

    var express = require('express')
        , cas = require('casable')
        , memstore =express.session.MemoryStore;//use session memory store ticket

    var app = express();
    app.use(express.cookieParser('your Secret'));
    app.use(express.session({
            store: MemStore({
            reapInterval: 60000 * 10
            }),
            secret: '1234567890QWERTY'
    }));
    
    app.use(cas.authentication('http://sso.com/cas', {
            logoutPath: '/logout',
            handleLogoutRequests:['10.8.11.7']//receive the post of logout from the ip
            casVersion: '1.0'
    }));
    
    app.use(app.router);//this must after app.use(cas.authentication)
    
    
```
