module.exports = {
    getAll: async function(req, res) {
       const {id} = req.session.user;
       const {showOwnBool} = req.params;
       const {search} = req.query;
 
       let posts = [];
 
       const db = req.app.get('db');
 
       // retrieve posts
       if (showOwnBool === 'true') {
          posts = await db.posts.get_all_with_user();
       } else {
          posts = await db.posts.get_all_without_user(id);
       }
 
       // filter retrieved posts if search was provided
       if (search) {
          const filteredPosts = posts.filter(post =>{
             return post.title.toLowerCase().includes(search.toLowerCase());
          });
 
          return res.status(200).json(filteredPosts);
       }
 
       res.status(200).json(posts);
    },
    getOne: async function(req, res) {
       const postId = parseInt(req.params.postId);
       
       const db = req.app.get('db');
 
       const post = await db.posts.get_one(postId);
 
       res.status(200).json(post[0]);
    },
    create: async function(req, res) {
       const {id} = req.session.user;
       const {title, img, content} = req.body;
 
       const db = req.app.get('db');
 
       await db.posts.create(id, title, img, content);
 
       res.sendStatus(200);
    }
 };