"use client";

import { useActionState, useState } from "react";

import handleForgottenPassword from "~/actions/handle-forgotten-password";

export default function ForgotPasswordForm() {
    const [submitted, setSubmitted] = useState(false);
    const [email, action, pending] = useActionState(handleForgottenPassword, "");
    const buttonText = !submitted ? "Next" : "Done";
    const message = submitted
        ? "You will receive a password reset link shortly (this is placeholder by the way)"
        : "";

    return (
        <form className="space-y-4 md:space-y-6" action={action}>
            <div>
                <label
                    htmlFor="email"
                    className="mb-2 block text-sm font-medium text-gray-900 dark:text-white"
                >
                    Email
                </label>

                <input
                    type="email"
                    name="email"
                    id="email"
                    className="focus:ring-primary-600 focus:border-primary-600 block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500"
                    placeholder="name@company.com"
                    defaultValue={email}
                    required
                />
            </div>

            <p aria-live="polite" className="text-sm">
                {message}
            </p>

            <button
                type="submit"
                className="btn btn-primary w-full rounded-lg"
                disabled={pending && !submitted}
                onClick={() => setSubmitted(true)}
            >
                {!pending ? (
                    buttonText
                ) : (
                    <span className="bg-primary loading loading-spinner"></span>
                )}
            </button>
        </form>
    );
}
