import React, {Component} from 'react';
import {Link} from 'react-router-dom';
import Axios from 'axios';

class Dashboard extends Component {
   constructor(props) {
      super(props);
      this.state = {
         search: '',
         showOwnPosts: true,
         posts: []
      };
      this.handleInputChange = this.handleInputChange.bind(this);
      this.handleGetPosts = this.handleGetPosts.bind(this);
      this.handleSearchReset = this.handleSearchReset.bind(this);
   }
   componentDidMount() {
      this.handleGetPosts();
   }
   handleGetPosts() {
      const {showOwnPosts, search} = this.state;

      Axios
         .get(`/api/posts/getAll/${showOwnPosts}?search=${search}`)
         .then(res => {
            this.setState({ 
               search: '',
               posts: res.data
            });
         })
         .catch(err => console.log(err.request));
   }
   handleInputChange(e) {
      const {name, value} = e.target;
      const {search} = this.state;

      if (name === 'search') {
         this.setState({ search: value });
      } else {
         this.setState({ showOwnPosts: !this.state.showOwnPosts }, () => {
            if (!search) this.handleGetPosts()
         })};
   }
   handleSearchReset() {
      this.setState({ search: '' }, () => this.handleGetPosts());
   }
   render() {
      
      const {posts} = this.state;

      const postsMapped = posts.length > 0
         ? posts.map(post => {
            return (
               <Link to={`/post/${post.id}`} key={post.id}>
                  <div>
                     <p>{post.title}</p>
                     <span>
                        <p>by {post.username}</p>
                        <img src={post.profile_pic} alt='User Post' />
                     </span>
                  </div>
               </Link>
            )})
         : 'No posts to show'

      return (
         <div>
            <input
               type='text'
               name='search'
               value={this.state.search}
               onChange={this.handleInputChange}
            />
            <button onClick={this.handleGetPosts}>Search</button>
            <button onClick={this.handleSearchReset}>Reset</button>
            <div>
               <p>My Posts</p>
               <input
                  type='checkbox'
                  name='showOwnPosts'
                  checked={this.state.showOwnPosts}
                  onChange={this.handleInputChange}
               />
            </div>
            {postsMapped}
         </div>
      );
   }
}

export default Dashboard