import airtable from "airtable";
import argon2 from "argon2";

import environment from "~/server/environment";

import type { ServerLoginCredentials } from "~/server/types";
import type { ClientLoginCredentials } from "~/shared/types";
import type { Record as AirtableRecord, FieldSet } from "airtable";

export interface User extends FieldSet {
    creationTimestamp: number;
    email: string;
    passwordHash: string;
}

export class DatabaseError extends Error {}

let cachedRecords: AirtableRecord<User>[];

class IncorrectPasswordError extends DatabaseError {
    constructor(email: string, options: Record<string, unknown> = {}) {
        super(`Incorrect password: ${email}`, options);
    }
}

class UserNotFoundError extends DatabaseError {
    constructor(email: string, options: Record<string, unknown> = {}) {
        super(`User not found: ${email}`, options);
    }
}

class UserExists extends DatabaseError {
    constructor(email: string, options: Record<string, unknown> = {}) {
        super(`User exists: ${email}`, options);
    }
}

airtable.configure({
    apiKey: environment.AIRTABLE_API_KEY,
});

const BASE = airtable.base(environment.AIRTABLE_BASE_ID);
const TABLE = BASE.table<User>(environment.AIRTABLE_TABLE_ID);

const fetchRecords = async () => {
    if (cachedRecords) {
        return cachedRecords;
    }

    const records = await TABLE.select({
        fields: ["email", "passwordHash", "creationTimestamp"],
    }).all();
    cachedRecords = Array.from(records);

    return cachedRecords;
};

async function logIn(credentials: ServerLoginCredentials): Promise<User> {
    const records = await fetchRecords();

    for (const record of records) {
        if (record.fields.email !== credentials.email) {
            continue;
        } else if (!(await argon2.verify(record.fields.passwordHash, credentials.password))) {
            throw new IncorrectPasswordError(credentials.email);
        }

        const user = record.fields;

        return user;
    }

    throw new UserNotFoundError(credentials.email);
}

async function signUp(credentials: ClientLoginCredentials): Promise<User> {
    const records = await fetchRecords();
    const userFound = records.find(record => record.fields.email === credentials.email);

    if (userFound) {
        throw new UserExists(credentials.email);
    }

    const newUser = {
        creationTimestamp: Date.now(),
        email: credentials.email,
        passwordHash: await argon2.hash(credentials.password),
    } satisfies User;
    const newUserRecord = await TABLE.create(newUser);

    cachedRecords.push(newUserRecord);

    return newUser;
}

export default {
    Error: DatabaseError,
    IncorrectPasswordError,
    UserExists,
    UserNotFoundError,
    logIn,
    signUp,
};
