var Sequelize = require('sequelize');
// var bcrypt = require('bcrypt');

var sequelize = new Sequelize('postgres://crga:28641028@10.17.0.1:5432/auth_kibana');

// setup User model and its fields.
var User = sequelize.define('users', {
    username: {
        type: Sequelize.STRING,
        unique: true,
        allowNull: false
    },
    password: {
        type: Sequelize.STRING,
        allowNull: false
    }
});

User.prototype.validPassword = function(password){
    console.log('password:'+password);
    console.log('password in DB:'+this.password);
    console.log(password==this.password);
    return password==this.password;
};


var UserRoles = sequelize.define('user_roles', {
    username: {
        type: Sequelize.STRING,
        unique: true,
        allowNull: false
    },
    roleId:{
        type: Sequelize.INTEGER,
        unique: true,
        allowNull: false
    }
});

var UserPerm = sequelize.define('user_perm', {
    username: {
        type: Sequelize.STRING,
        unique: true,
        allowNull: false
    },
    permission:{
        type: Sequelize.JSON,
        unique: false,
        allowNull: true
    }
});





// create all the defined tables in the specified database.
sequelize.sync()
    .then(() => console.log('users table has been successfully created, if one doesn\'t exist'))
    .catch(error => console.log('This error occured', error));

// export User model for use in other files.
module.exports = {User,UserRoles,UserPerm};