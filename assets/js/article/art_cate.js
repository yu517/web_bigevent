$(function() {
    var layer = layui.layer
    var form = layui.form
    initArtCateList()

    // 获取文章分类的列表
    function initArtCateList() {
        $.ajax({
            method: 'GET',
            url: '/my/article/cates',
            success: function(res) {
                // console.log(res)
               var htmlStr = template('tpl-table', res)
               $('tbody').html(htmlStr)
            }
        })
    }

    // 为 添加类别 按钮绑定点击事件
    var indexAdd = null 
    $('#btnAddCate').on('click', function() {
        indexAdd = layer.open({
            type: 1, // 页面层
            area: ['500px', '250px'],
            title: '添加文章分类',
            content: $('#dialog-add').html()
        })
    })

    // form-add 是动态生成的，所以需要通过代理的形式，为 form-add 表单绑定 submit 事件
    $('body').on('click', '#form-add', function(e) {
        e.preventDefault()
        // console.log('ok')
        $.ajax({
            method: 'POST',
            url: '/my/article/addcates',
            data: $(this).serialize(),
            success: function (res) {
                if(res.status !== 0) {
                    return layer.msg('新增分类失败！')
                }
                initArtCateList()
                return layer.msg('新增分类成功！')
                // 根据索引，关闭对应的弹出层
                layer.close(indexAdd)
            }

        })
    })

    // 通过代理的形式，为 btn-edit 按钮绑定点击事件
    var indexEdit = null 
    $('tbody').on('click', '.btn-edit', function() {
        // console.log(ok)
        // 弹出一个修改文章分类信息的层
        indexEdit = layer.open({
            type: 1, // 页面层
            area: ['500px', '250px'],
            title: '修改文章分类',
            content: $('#dialog-edit').html()
        })
    })
     
    var id = $(this).attr('data-id')
    // console.log(id)
    // 发起请求获取对应分类的数据
    $.ajax({
        method: 'GET',
        url: '/my/article/deletecate/' + id,
        success: function (res) {
            // console.log(res)
            // 快速为表单填充数据
            // 参数1：为哪个表格填充， 参数2：填充什么数据
            form.val('form-edit', res.date)
        }
    })

    // 通过代理的形式，为修改分类的表单绑定 submit 事件
    $('body').on('submit', '#form-edit', function(e) {
        e.preventDefault()
        $.ajax({
            method: 'POST',
            url: '/my/article/updatecate',
            data: $(this).serialize(),
            success: function(res) {
                if(res.status !== 0) {
                    return layer.msg('更新分类数据失败！')
                }
                layer.msg('更新分类数据成功！')
                layer.close(indexEdit)
                initArtCateList()
            }
        })
    })

    // 通过代理的形式，为删除按钮绑定点击事件
    $('tbody').on('click', '.btn-delete', function() {
        // console.log('ok')
        var id = $(this).attr('data-id')
        // 提示用户是否删除
        // function(index){} 点击确认后执行的函数
        layer.confirm('确认删除?', {icon: 3, title:'提示'}, function(index){
            $.ajax({
                method: 'GET',
                url: '/my/article/deletecate/' + id,
                success: function(res) {
                    if(res.status !== 0) {
                        return layer.msg('删除分类失败！')
                    }
                    layer.msg('删除分类成功！')
                    layer.close(index)
                    initArtCateList()
                }
            })
        })
    })
})