"use server";

import Link from "next/link";

import ForgotPasswordForm from "~/components/client/forgot-password-form";

export default async function ForgotPassword() {
    return (
        <section className="bg-gray-50 dark:bg-gray-900">
            <div className="mx-auto flex flex-col items-center justify-center px-6 py-8 md:h-screen lg:py-0">
                <Link
                    href="/"
                    className="mb-6 flex items-center text-2xl font-semibold text-gray-900 dark:text-white"
                >
                    Accounts with Airtable
                </Link>

                <div className="w-full rounded-lg bg-white shadow sm:max-w-md md:mt-0 xl:p-0 dark:border dark:border-gray-700 dark:bg-gray-800">
                    <div className="space-y-4 p-6 sm:p-8 md:space-y-6">
                        <div className="space-y-2">
                            <h1 className="text-xl leading-tight font-bold tracking-tight text-gray-900 md:text-2xl dark:text-white">
                                Forgot your password?
                            </h1>
                            <p className="text-sm">
                                We can send you a password recovery email, please enter your email
                                below
                            </p>
                        </div>

                        <ForgotPasswordForm />
                    </div>
                </div>
            </div>
        </section>
    );
}
