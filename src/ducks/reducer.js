const initialState = {
  username: '',
  profilePic: ''
};

const UPDATE_USER = 'UPDATE_USER';

export function updateUser(username, profilePic) {

  return {
     type: UPDATE_USER,
     payload: {username, profilePic}
  }
}

export default function reducer(state = initialState, action) {
  const {type, payload} = action;

  switch(type) {
     case UPDATE_USER:
        const {username, profilePic} = payload;

        return {
           ...state,
           username,
           profilePic
        }
     default: return state;
  }
}