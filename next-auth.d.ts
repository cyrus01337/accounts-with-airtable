import type { User as UserFromDatabase } from "~/server/database";

declare module "next-auth" {
    type User = UserFromDatabase;
}
