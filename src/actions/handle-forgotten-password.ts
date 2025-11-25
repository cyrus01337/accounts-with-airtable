export default async function handleForgottenPassword(
    _previousState: unknown,
    formData: FormData,
): Promise<string> {
    return formData.get("email") as string;
}
