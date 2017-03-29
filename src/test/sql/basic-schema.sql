CREATE TABLE users (
  uid int,
  name varchar(64),
  pass varchar(64)
);
INSERT INTO users (uid, name, pass) VALUES (0, '', '');
INSERT INTO users (uid, name, pass) VALUES (1, 'alpha', 'first');
INSERT INTO users (uid, name, pass) VALUES (2, 'bravo', 'second');
INSERT INTO users (uid, name, pass) VALUES (3, 'charlie', 'third');


CREATE TABLE users_roles (
  uid int,
  rid int
);
INSERT INTO users_roles (uid, rid) VALUES (1, 0);
INSERT INTO users_roles (uid, rid) VALUES (1, 1);
INSERT INTO users_roles (uid, rid) VALUES (1, 2);
INSERT INTO users_roles (uid, rid) VALUES (2, 1);


CREATE TABLE role (
  rid int,
  name varchar(64)
);
INSERT INTO role (rid, name) VALUES (0, 'first role');
INSERT INTO role (rid, name) VALUES (1, 'second role');
INSERT INTO role (rid, name) VALUES (2, 'third role');
