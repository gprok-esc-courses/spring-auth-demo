INSERT INTO roles (name) VALUES ('ADMIN')
INSERT INTO roles (name) VALUES ('EDITOR')
INSERT INTO roles (name) VALUES ('AUTHOR')
INSERT INTO roles (name) VALUES ('USER')

INSERT INTO users (username, password, enabled) VALUES ('admin', '1111', 1)
INSERT INTO users (username, password, enabled) VALUES ('john', '1111', 1)
INSERT INTO users (username, password, enabled) VALUES ('mary', '1111', 1)
INSERT INTO users (username, password, enabled) VALUES ('peter', '1111', 1)
INSERT INTO users (username, password, enabled) VALUES ('ann', '1111', 1)

INSERT INTO users_roles (user_id, role_id) VALUES (1, 1)
INSERT INTO users_roles (user_id, role_id) VALUES (2, 2)
INSERT INTO users_roles (user_id, role_id) VALUES (2, 3)
INSERT INTO users_roles (user_id, role_id) VALUES (3, 3)
INSERT INTO users_roles (user_id, role_id) VALUES (4, 4)
INSERT INTO users_roles (user_id, role_id) VALUES (5, 4)