// 导入数据库操作模块
const db = require('../db/index')
// 导入 bcrypt.js 这个包
// bcrypt.js是nodejs中比较好的一款加盐(salt)加密的包.
// 所谓加盐.就是系统生成一串随机值,然后混入原始密码中,然后按照加密方式生成一串字符串保存在服务器。
const bcrypt = require('bcryptjs')
// 导入生成 token 的包
const jwt = require('jsonwebtoken')
// 导入全局的配置文件
const config = require('../config')

// 注册新用户的处理函数
exports.regUser = (req, res) => {
    // 获取客户端提交到服务器的用户信息
    const userinfo = req.body
    // console.log(userinfo)
    // 对表单中的数据，进行合法性的校验
    /* if(!userinfo.username || !userinfo.password) {
        return res.send({
            status:1,
            message: '用户名或密码不合法！'
        })
    } */


    // res.send('reguser OK')

    // 定义 SQL 语句，进行合法性的校验
    const sqlStr = 'select * from ev_users where username=?'
    db.query(sqlStr, userinfo.username, (err, results) => {
        // 执行 SQL 语句失败
        if(err) {
            // return res.send({status:1, message: err.message})
            return res.cc(err)
        }
        // 判断用户名是否被占用
        if(results.length > 0) {
            // return res.send({status: 1, message: '用户名被占用，请更换其他用户名！'})
            return res.cc('用户名被占用，请更换其他用户名！')

        }
        
    })
    // 调用 bcrypt.hashSync() 对密码进行加密
    userinfo.password = bcrypt.hashSync(userinfo.password, 10)
    /* 加密处理 - 同步方法
 * bcryptjs.hashSync(data, salt)
 *    - data  要加密的数据
 *    - slat  用于哈希密码的盐。如果指定为数字，则将使用指定的轮数生成盐并将其使用。推荐 10 
 *    let hasPwd=bcryptjs.hashSync(password, 10)
 * 注意：每次调用输出都会不一样 */
    // console.log(userinfo)
    // console.log(userinfo)
    // 定义插入新用户的 SQL 语句
    const sql = 'insert into ev_users set ?' 
    // 调用db.query() 执行 SQL 语句
    db.query(sql, {username: userinfo.username, password: userinfo.password}, (err, results) => {
        // 判断 SQL 语句是否执行成功
        // if(err)  return res.send({status:1, message: err.message})
        if(err) return res.cc(err)
        
        // 判断影响行数是否为1
        // if(results.affectedRows !==1) return res.send({status: 1, message: '注册用户失败，请稍后再试！'})
        if(results.affectedRows !==1) return res.cc('注册用户失败，请稍后再试！')
        // 注册用户成功
        // res.send({status: 0, message: '注册成功！'})
        res.cc('注册成功！', 0)
    })
}


// 登录的处理函数
exports.login = (req, res) => {
    // 接收表单的数据
    const userinfo = req.body
    // 定义 SQL 语句
    const sql = `select * from ev_users where username=?`
    // 执行 SQL 语句，根据用户查询用户的信息
    db.query(sql, userinfo.username, (err, results) => {
        // 执行 SQL 语句失败
        if(err) return res.cc(err)
        // 执行 SQL 语句成功，但是获取到的数据条数不等于1 
        if(results.length !== 1) return res.cc('登录失败！')

        // TODO: 判断密码是否正确
        const compareResult = bcrypt.compareSync(userinfo.password, results[0].password)
        if(!compareResult) return res.cc('登录失败！')
        /*  校验 - 使用同步方法
 * bcryptjs.compareSync(data, encrypted)
 *    - data        要比较的数据, 使用登录时传递过来的密码
 *    - encrypted   要比较的数据, 使用从数据库中查询出来的加密过的密码
 *      let comparePwd=bcryptjs.compareSync(password,'$2a$10$OIYc/KLDcBdHf8Ww9uKbG.CLxdGBMLSQ0h7l4c0G7ED7.fqmpb4B6');
 *      console.log(comparePwd);//true */

        // res.send('ok')

        // TODO：在服务器端完成 Token 的字符串
        const user = {...results[0], password: '', user_pic: ''}
        // console.log(user)
        // 对用户的信息进行加密，生成 Token字符串
        const tokenStr = jwt.sign(user, config.jwtSecretKey, {expiresIn: config.expiresIn})
        // console.log(tokenStr)
        // 调用 res.send() 将 Token 响应给客户端
        res.send({
            status: 0,
            message: '登录成功！',
            token: 'Bearer ' + tokenStr,
        })
    })
}