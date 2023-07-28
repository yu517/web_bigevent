// 导入定义验证规则的包 
const joi = require('joi')

// 定义用户名和密码的验证规则
const username = joi.string().alphanum().min(1).max(10).required()
const password = joi.string().pattern(/^[\S]{6,12}$/).required()

// 定义 id, nickname, email 的验证规则
const id = joi.number().integer().min(1).required()
const nickname = joi.string().required()
const email = joi.string().email().required()

// 定义验证 avatar 头像的验证规则
const avatar = joi.string().dataUri().required()

// 定义验证注册或登录的表单数据的规则对象
exports.reg_login_schema = {
    body : {
        username,
        password,
    }
}

// 验证规则对象 - 更新用户基本信息
exports.update_userinfo_schema = {
    // 需要对 req.body 里面的数据进行验证
    body: {
        id: id, // 验证 body 里面的id : 验证规则，两者名字相同可简写(只写一个)
        nickname: nickname, // 如果表单里面数据的名字和对应验证规则的名字，不相同就需要进行冒号的指定
        email: email,
    }
}

// 验证规则对象 - 更新密码
exports.update_password_schema = {
    body: {
        oldPwd: password,
        // ref() newPwd与oldPwd保持一致，not() 排除，concat()  连接或合并多条规则
        newPwd: joi.not(joi.ref('oldPwd')).concat(password),
    }
}

// 验证规则对象 - 更新头像
exports.update_avatar_schema = {
    body: {
        avatar
    }
}