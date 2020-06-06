SELECT p.id, p.title, u.username, u.profile_pic
FROM posts p
INNER JOIN users u ON p.author_id = u.id
WHERE p.author_id != $1
ORDER BY p.id DESC;