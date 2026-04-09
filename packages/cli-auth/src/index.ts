export function createCliAuth(config: { strategy: "static-token"; token: string }) {
  return {
    async getToken() {
      return config.token;
    },
    async status() {
      return { authenticated: true, strategy: "static-token" as const };
    },
  };
}
