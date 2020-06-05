create table users (
  user_id serial primary key,
  username varchar(50),
  password text,
  profile_pic text
);
create table posts (
  post_id serial primary key,
  title varchar(45),
  img text,
  content text,
  author_id int references users(user_id)
);