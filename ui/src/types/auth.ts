export interface LoginRequest {
    username: string;
    password: string;
}

export interface LoginResponse {
    token: string;
    user: User;
}

export interface User {
    id: number;
    username: string;
    email: string;
    role: Role;
    status: UserStatus;
}

export interface Role {
    id: number;
    name: RoleName;
    level: RoleLevel;
    status: RoleStatus;
}

export enum UserStatus {
    Active = 'active',
    Inactive = 'inactive',
    Locked = 'locked',
    Deleted = 'deleted',
    Unknown = 'unknown',
}

export enum RoleName {
    Admin = 'admin',
    User = 'user',
    Auditor = 'auditor',
}

export enum RoleLevel {
    Admin = 1,
    User = 2,
    Auditor = 3,
}

export enum RoleStatus {
    Normal = 'normal',
    Disabled = 'disabled',
    Unknown = 'unknown',
}
