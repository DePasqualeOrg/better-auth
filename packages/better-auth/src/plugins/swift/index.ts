import type { BetterAuthPlugin } from "../../types/plugins";
import { createAuthMiddleware } from "../../api";
import { parseSetCookieHeader } from "../../cookies";

export interface SwiftOptions {
  /**
   * Override the URL scheme that will be recognized as Swift App URL scheme
   * If not provided, will use better-auth:// as the default scheme
   */
  scheme?: string;
}

/**
 * Plugin for Swift client support
 * Adds session token to callback URL query parameters
 */
export const swift = (options?: SwiftOptions) => {
  // Get the scheme from options or use default
  const scheme = options?.scheme || "better-auth";
  
  return {
    id: "swift",
    init: (ctx) => {
      // Add the scheme to trusted origins if not already present
      const trustedOrigins = [...(ctx.trustedOrigins || [])];
      const schemePattern = `${scheme}://`;
      
      if (!trustedOrigins.some(origin => origin.startsWith(schemePattern))) {
        trustedOrigins.push(schemePattern);
      }
      
      return {
        options: {
          trustedOrigins,
        },
      };
    },
    hooks: {
      after: [
        {
          matcher(context) {
            return (
              context.path?.startsWith("/callback") ||
              context.path?.startsWith("/oauth2/callback")
            );
          },
          handler: createAuthMiddleware(async (ctx) => {
            const headers = ctx.context.responseHeaders;
            const location = headers?.get("location");
            if (!location) {
              return;
            }
            
            // Check if this is a redirect to our Swift app
            const schemePattern = `${scheme}://`;
            if (!location.startsWith(schemePattern)) {
              return;
            }
            
            // Get the session cookie
            const setCookie = headers?.get("set-cookie");
            if (!setCookie) {
              return;
            }
            
            // Extract the session token from the cookie
            const parsedCookies = parseSetCookieHeader(setCookie);
            const cookieName = ctx.context.authCookies.sessionToken.name;
            const sessionCookie = parsedCookies.get(cookieName);
            
            if (!sessionCookie || !sessionCookie.value) {
              return;
            }
            
            // Add the token to the redirect URL
            const url = new URL(location);
            url.searchParams.set("set-auth-token", sessionCookie.value);
            ctx.setHeader("location", url.toString());
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
};