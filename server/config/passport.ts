import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { authService } from '../services/auth.service';
import { storage } from '../storage';

// Configure local strategy
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
  try {
    const result = await authService.login({ email, password });
    return done(null, result.user);
  } catch (error) {
    return done(null, false, { message: error.message });
  }
}));

// Serialize user for session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await storage.getUser(id);
    if (user) {
      const { passwordHash: _, mfaSecret: __, ...userWithoutSensitiveData } = user;
      done(null, userWithoutSensitiveData);
    } else {
      done(null, false);
    }
  } catch (error) {
    done(error, null);
  }
});

export default passport;
