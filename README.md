# Shopme
clone this project

# Setup Database

Create user:

CREATE USER 'shopmeuser'@'localhost' IDENTIFIED BY '456$%^shopme';<br>
GRANT ALL PRIVILEGES ON * . * TO 'shopmeuser'@'localhost';<br>
ALTER USER 'shopmeuser'@'localhost' IDENTIFIED WITH mysql_native_password BY '456$%^shopme';<br>

Create database "shopme" and "shopme_test":

DROP SCHEMA IF EXISTS `shopme`;<br>
CREATE SCHEMA `shopme`;<br>
DROP SCHEMA IF EXISTS `shopme_test`;<br>
CREATE SCHEMA `shopme_test`;<br>

see sql scripts at shopme/db

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/database.png)

# Run Project

Run ShopmeBackEndApplication.java then visit http://localhost:8080/ShopmeAdmin/

Or you can test add many users right away.
Open UserServiceTest.java. Go to line 251 and run unit test 
method testAddManyUsers(). Make sure it succeeds.

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/unit-test-add-users.png)


# Using the project

Go to http://localhost:8080/ShopmeAdmin/Login. Use this initial credentials of first user:
email: superuser@gmail.com
pass: superuser@gmail.com

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/login.png)

Users page

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/users.png)

Add user form

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/create-users.png)

Edit user form

![Initializer](https://raw.githubusercontent.com/raymond-tiongco/shopme/daryll-shopme/guides/edit-user.png)

test