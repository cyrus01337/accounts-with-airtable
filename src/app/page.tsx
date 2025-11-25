"use client";

import { signIn, signOut } from "next-auth/react";
import Link from "next/link";

import IfLoadingSession from "~/components/client/if-loading-session";
import IfNoSession from "~/components/client/if-no-session";
import IfSession from "~/components/client/if-session";

const BUTTON_CLASS = "btn btn-primary min-w-24";

export default function Home() {
    return (
        <main>
            <div className="flex flex-row gap-2">
                <IfLoadingSession>
                    <button className={BUTTON_CLASS}>
                        <span className="loading loading-spinner"></span>
                    </button>
                </IfLoadingSession>

                <IfNoSession>
                    <a className={BUTTON_CLASS} onClick={() => signIn()}>
                        Login
                    </a>

                    <Link className={BUTTON_CLASS} href="/sign-up">
                        Sign Up
                    </Link>
                </IfNoSession>

                <IfSession>
                    <button
                        className={BUTTON_CLASS}
                        onClick={() => signOut({ callbackUrl: "/", redirect: true })}
                    >
                        Logout
                    </button>
                </IfSession>
            </div>
        </main>
    );
}
