SELECT p.id, p.title, u.username, u.profile_pic
FROM posts p
INNER JOIN users u ON p.author_id = u.id
ORDER BY p.id DESC;