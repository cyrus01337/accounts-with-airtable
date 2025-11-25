export interface ClientLoginCredentials {
    email: string;
    password: string;
}

export interface LoginResponse {
    credentials: ClientLoginCredentials;
    errors: string[];
    message: string;
}
