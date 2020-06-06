import React, {Component} from 'react';
import Axios from 'axios';

class Post extends Component {
   constructor(props) {
      super(props);
      this.state = {
          post: {}
      };
   }
   componentDidMount() {
      const {postId} = this.props.match.params;

      Axios
         .get(`/api/posts/getOne/${postId}`)
         .then(res => this.setState({ post: res.data }))
         .catch(err => console.log(err.request));
   }
   render() {

      const {username, profile_pic: profilePic, title, img, content} = this.state.post;

      return (
         <div>
            <span>
               <h1>{title}</h1>
               <span>
                  <p>by {username}</p>
                  <img src={profilePic} alt='User Avatar' />
               </span>
            </span>
            <span>
               <img src={img} alt='Post Visual' />
               <p>{content}</p>
            </span>
         </div>
      );
   }
}

export default Post