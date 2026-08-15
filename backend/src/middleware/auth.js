'use strict';
const { verifyAccessToken } = require('../utils/jwt'); const { UnauthorizedError } = require('../utils/errors'); const db = require('../db');
function requireAuth(req,res,next){
 const header=req.headers.authorization||''; const [scheme,token]=header.split(' '); if(scheme!=='Bearer'||!token)return next(new UnauthorizedError('Missing or malformed Authorization header'));
 try{const payload=verifyAccessToken(token); const user=db.prepare('SELECT id,email,role,status,password_changed_at FROM users WHERE id = ?').get(payload.sub); if(!user||user.status!=='active')throw new Error('account_unavailable');
  if(user.password_changed_at && payload.iat && payload.iat < Math.floor(new Date(user.password_changed_at).getTime()/1000)) throw new Error('token_revoked');
  req.user={id:user.id,role:user.role,email:user.email}; return next();
 }catch(err){return next(new UnauthorizedError('Invalid, expired, or revoked access token'));}
}
module.exports={requireAuth};
