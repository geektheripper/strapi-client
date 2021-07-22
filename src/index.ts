import axios, { AxiosInstance } from "axios";
import jwt from "jsonwebtoken";

export interface TokenStoreProvider {
  save(token: string): Promise<void>;
  load(): Promise<string>;
}

export interface ApiOptions {
  baseURL: string;
  identifier: string;
  password: string;
  storeProvider?: TokenStoreProvider;
}

export class Api {
  instance: AxiosInstance;

  constructor({ baseURL, identifier, password, storeProvider }: ApiOptions) {
    this.instance = axios.create({ baseURL });

    let tokenNotLoaded = true;
    let token = "";
    let tokenExpirationTime = 0;

    const tokenExpired = () =>
      new Date().getTime() - tokenExpirationTime > 60 * 1000;

    const applyToken = (token: string) => {
      const payload = jwt.decode(token) as jwt.JwtPayload;
      tokenExpirationTime = (payload?.exp as number) * 1000;
    };

    this.instance.interceptors.request.use(async (config) => {
      if (tokenNotLoaded && storeProvider)
        applyToken(await storeProvider.load());

      if (tokenExpired()) {
        const { data } = await this.instance.post("/auth/local", {
          identifier,
          password,
        });
        applyToken(data.jwt);
        storeProvider?.save(data.jwt);
      }

      config.headers["Authorization"] = `Bearer ${token}`;

      return config;
    });
  }
}
