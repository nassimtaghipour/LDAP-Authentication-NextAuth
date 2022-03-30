



import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import ldap from "ldapjs";

export default NextAuth({
  providers: [
    CredentialsProvider({
      name: "LDAP",
      credentials: {
        username: {
          label: "UserName",
          type: "text",
          placeholder: ""
        },
        password: { label: "Password", type: "password" }
      },

      async authorize(credentials, req) {
        const client = ldap.createClient({
        url: process.env.LDAP_URI,
          // this line is added to ignore ssl certificate
          tlsOptions: { rejectUnauthorized: false }
        });
        var user = {};
        var opts = {
          filter: `(uid=${credentials.username})`,
          scope: "sub",
          attributes: ["dn", "sn", "cn", "uid"]
        };
        // search function
        return new Promise((resolve, reject) => {
          client.search(
            "ou=addyouruser,dc=addyourdc,dc=addyourdc,dc=addyourde",
            opts,
            function (err, res) {
              if (err) {
                console.log("Error occurred while ldap search");
                reject(err);
              } else {
                var entries = [];
                res.on("searchEntry", function (entry) {
                  entries.push(entry.object);
                  client.bind(
                    entry.object.dn,
                    credentials.password,
                    (error) => {
                      if (error) {
                        console.error("login failed");
                        reject(error);
                      } else {
                        console.log("Logged in");
                        user.name = entry.object.cn;
                        console.log("logedin user", user);

                        resolve({
                          uid: entry.object.uid,
                          username: entry.object.cn,
                          password: credentials.password
                        });
                      }
                    }
                  );
                });
                res.on("searchReference", function (referral) {
                  console.log("Referral", referral);
                });
                res.on("error", function (err) {
                  console.log("Error is", err);
                  reject();
                });
                res.on("end", function (result) {
                  console.log("Result is", result);
                  let entrylength = entries.length;
                  if (entrylength <= 0) {
                    reject("Invalid Credentials");
                  }
                });
              }
            }
          );
        });
      }
    })
  ],
  theme: {
    colorScheme: "light", // "auto" | "dark" | "light"
    brandColor: "", // Hex color code
    logo: "" // Absolute URL to image
  },
  pages: {
    signIn: "/auth/signin",
    error: "/auth/signin" // Error code passed in query string as ?error=
  },

  callbacks: {
    session: {
      jwt: true,
      maxAge: 30 * 24 * 60 * 60
    },

    async session({ session, token }) {
      return {
        ...session,
        username: { name: token.username, uid: token.uid }
      };
    },

    async jwt({ token, user }) {
      const isSignIn = user ? true : false;
      if (isSignIn) {
        token.username = user.username;
        token.password = user.password;
        token.uid = user.uid;
      }
      return token;
    }
  }
});
