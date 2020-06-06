import React, {Component} from 'react';
import Axios from 'axios';
import {withRouter, Link} from 'react-router-dom';
import {connect} from 'react-redux';
import {updateUser} from '../../ducks/reducer';

class Nav extends Component {
   constructor(props) {
      super(props);
      this.state = {
         editMode: false,
         userName: ''
      }
      this.handleLogout = this.handleLogout.bind(this);
      this.handleInputChange = this.handleInputChange.bind(this);
      this.handleInputSubmit = this.handleInputSubmit.bind(this);
      this.updateUserInfo = this.updateUserInfo.bind(this);
   }
   componentDidMount() {
      this.updateUserInfo();
   }
   componentDidUpdate(prevProps) {
      if (prevProps.username !== this.props.username && !!this.props.username) alert(`Welcome, ${this.props.username}!`);
   }
   updateUserInfo() {
      Axios
         .get('/api/auth/me')
         .then(res => this.props.updateUser(res.data.username, res.data.profilePic))
         .then(this.setState({ 
            userName: this.props.userName,
            editMode: false
          }))
         .catch(err => console.log(err.request));
   }
   handleInputChange(e) {
      const {name, value, id} = e.target;

      if (id === 'editMode') return this.setState({ editMode: true });

      this.setState({ [name]: value })
   }
   handleInputSubmit() {
      Axios
         .put(`/api/auth/updateusername/${this.state.userName}`)
         .then(() => this.updateUserInfo())
         .catch(err => console.log(err.request));
   }
   handleLogout() {
      Axios
         .post('/api/auth/logout')
         .then(() => {
            this.props.updateUser('','');
            this.props.history.push('/');
         })
         .catch(err => console.log(err.request));
   }
   render() {
      return (
         <>
            {this.props.location.pathname === '/'
            ? null
            : (
               <div>
                  <span>
                     {this.state.editMode
                     ?  <>
                           <input
                              type='text'
                              value={this.state.userName}
                              name='userName'
                              onChange={this.handleInputChange}
                           />
                           <button onClick={this.handleInputSubmit}>Submit!</button>
                        </>
                     :  <h1 
                           id='editMode' 
                           onClick={this.handleInputChange}>{this.props.username}
                        </h1>
                     }
                     <img src={this.props.profilePic} alt='User Avatar' />
                  </span>

                  <ul>
                     <li><Link to='/dashboard'><button>Home</button></Link></li>
                     <li><Link to='/new'><button>New Post</button></Link></li>
                     <li><button onClick={this.handleLogout}>Logout</button></li>
                  </ul>
               </div>
            )}
         </>
      );
   }
}

const mapStateToProps = reduxState => {
   const {username, profilePic} = reduxState;
   return {
      username, profilePic
   }
};

export default withRouter(connect(mapStateToProps, {
   updateUser
})(Nav))