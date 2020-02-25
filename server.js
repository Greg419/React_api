/*
    Refer to the "Module" of Json Server
    https://github.com/typicode/json-server
*/

// it’s better to use an absolute path
const path = require('path')
const fs = require('fs'); // 讀取檔案用

// JSON Web Token(JWT) 簡單介紹 https://mgleon08.github.io/blog/2018/07/16/jwt/
const jwt = require('jsonwebtoken'); // 註冊jwt驗證

const jsonServer = require('json-server')
const server = jsonServer.create()
// const router = jsonServer.router('db.json')
const router = jsonServer.router(path.join(__dirname, 'db.json'))
const middlewares = jsonServer.defaults()

server.use(jsonServer.bodyParser);
server.use(middlewares)

// 讀取檔案 users.json, 並轉為JSON格式
const getUsersDb = () => {
    return JSON.parse(
        fs.readFileSync(path.join(__dirname, 'users.json'), 'UTF-8')
    );
};

// 驗證 db.user 與 使用者輸入的email, password
const isAuthenticated = ({email,password}) => {
    return( 
        getUsersDb().users.findIndex(
            user => user.email === email && user.password === password
        ) !== -1 // 有比對到任一組 user, 會回傳 >= 0 的 index 值
    );
};

// 只根據郵箱判斷是否已存在
const isExist = email => {
    return getUsersDb().users.findIndex(user => user.email === email) !== -1;
};

const SECRET = 'JOIEJ039480IOJQ2043UF0K0Q9284'
// auth.js 在 decode(token) 後會得到一個屬性 exp 的時間戳, 與 expiresIn 給的值相關
const expiresIn ='1h'

// https://github.com/auth0/node-jsonwebtoken
// to see how to "generate a token" by Sign 
const createToken = payload => {
    return jwt.sign(payload, SECRET, { expiresIn });
};

// 自定義 post 接收請求接口: 格式驗證正確"回傳一組Token", 否則回傳401訊息
server.post('/auth/login', (req, res)=>{
    const { email, password } = req.body; // postman 傳過來的 user 登入資料
    
    if(isAuthenticated({email, password})){
        console.log(getUsersDb());
        const user = getUsersDb().users.find(
            u => u.email === email && u.password === password
        );
        const { nickname, type } = user;
        
        // ***** 產生 jw token *****
        const jwToken = createToken({ email, nickname, type });
        
        return res.status(200).json(jwToken) // 以 json 形式將 jwToken 返回給user
    }else{
        const status = 401;
        const message = 'Incorrect email or password';
        return res.status(status).json({ status, message });
    }
    
    console.log('Login Success!'); // print to cmd
    return res.status(200).json('Login Success!'); // print to page
});

// Register New User
server.post('/auth/register', (req, res)=>{
    const { email, password, nickname, type } = req.body;
    
    // ----- step1. 判斷user是否已存在
    if(isExist(email)){
        const status = 401;
        const message = 'Email or Password already exist';
        return res.status(status).json({ status, message });
    }
    
    // ----- step2. 不存在就將資料寫進 users.json
    fs.readFile(path.join(__dirname, 'users.json'), (err, _data) => {
        if(err) {
            const status = 401;
            const message = err;
            return res.status(status).json({ status, message });
        }
        // Get current users data
        const data = JSON.parse(_data.toString());
        // Get the id of last user
        const last_item_id = data.users[data.users.length - 1].id;
        // Add new user to json obj
        data.users.push({ id: last_item_id, email, password, nickname, type }); // add some data
        // Write the data to users.json
        fs.writeFile(
            path.join(__dirname, 'users.json'),
            JSON.stringify(data),
            (err , result) => {
                // WRITE
                if(err) {
                    const status = 401;
                    const message = err;
                    res.status(status).json({ status, message });
                    return;
                }
            }
        );
    });
    
    //Create token for new user
    const jwToken = createToken({ nickname, type, email });
    res.status(200).json(jwToken);
});


/*             接管某端口, 並驗證 user 傳過來的 Token

req的格式 -->  Authorization:(空白)Bearer(空白)Token

request headers --> Authorization

Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJlbWFpbCI6ImFkbWluMkBnbWFpbC5jb20iLCJuaWNrbmFtZSI6ImFkbWluMiIsInR5cGUiOjEsImlwfQ
.M2dp2xgEhbmKzYvL0Rn5vGsUzaBXClQDdhB0PBwCSoY

*/

// 接管 json server 的 db.json 訪問權限, 用 ['/carts', ...] 可接管多個路由
// server.user(['/carts'], (req, res, next) => {
server.use('/carts', (req, res, next) => {
    // 判斷請求格式是否符合 JWT header
    if(
        //https://www.cnblogs.com/itbsl/p/10412924.html
        req.headers.authorization === undefined ||
        req.headers.authorization.split(' ')[0] !== 'Bearer' // 沒有拿到 Bearer類型的
    ) {
        const status = 401;
        const message = 'Error in authorization format';
        res.status(status).json({ status, message });
        return;
    }
    try {
        const verifyTokenResult = verifyToken(
            req.headers.authorization.split(' ')[1]
        );
        if (verifyTokenResult instanceof Error) {
            const status = 401;
            const message = 'Access token not provided';
            res.status(status).json({ status, message });
            return;
        }
        next(); // 調用後, 繼續處理原始 /carts 的請求 => 將db內carts相關資訊返回
    } catch(err) {
        const status = 401;
        const message = 'Error token is revoked';
        res.status(status).json({ status, message });
    }
});

// Verify the token, 驗證通過則回傳驗證結果 decode
const verifyToken = token => {
    return jwt.verify(token, SECRET, (err, decode) =>
        decode !== undefined ? decode : err
    );
};

server.use(router)
server.listen(3003, () => {
  console.log('JSON Server is running')
})