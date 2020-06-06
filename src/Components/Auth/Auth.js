 import React, {Component} from 'react';
import Axios from 'axios';
import {connect} from 'react-redux';
import {updateUser} from '../../ducks/reducer';

class Auth extends Component {
    constructor(props) {
       super(props);
       this.state = {
           username: 'happyuser',
           password: 'password'
       };
       this.handleInputChange = this.handleInputChange.bind(this);
       this.handleLogin = this.handleLogin.bind(this);
       this.handleRegister = this.handleRegister.bind(this);
    }
    handleInputChange(e) {
       const {name, value} = e.target;
       this.setState({ [name]: value });
    }
    handleLogin() {
       const {username, password} = this.state;
 
       if (!username || !password) return alert('One or more fields are blank');
 
       Axios
          .post('/api/auth/login', {username, password})
          .then(res => {
             this.props.updateUser(res.data.username, res.data.profilePic);
             this.props.history.push('/dashboard');
          })
          .catch(err => console.log(err.request));
    }
    handleRegister() {
       const {username, password} = this.state;
 
       if (!username || !password) return alert('One or more fields are blank');
 
       Axios
          .post('/api/auth/register', {username, password})
          .then(res => {
             this.props.updateUser(res.data.username, res.data.profilePic);
             this.props.history.push('/dashboard');
          })
          .catch(err => console.log(err.request));
    }
    render() {
       return (
          <div>
             <h1>
                <span role='img' aria-label='Wink Emoji' aria-describedby='sitename'>
                   😉
                </span>
             </h1>
             <h1 id='sitename'>Helo</h1>
             <span>
                <label>Username</label>
                <input
                   type='text'
                   value={this.state.username}
                   placeholder='username'
                   name='username'
                   onChange={this.handleInputChange}
                />
             </span>
             <span>
                <label>Password</label>
                <input
                   type='text'
                   value={this.state.password}
                   placeholder='password'
                   name='password'
                   onChange={this.handleInputChange}
                />
             </span>
             <span>
                <button onClick={this.handleLogin}>Login</button>
                <button onClick={this.handleRegister}>Register</button>
             </span>
          </div>
       );
    }
 }
 
 export default connect(null, {
    updateUser
 })(Auth)