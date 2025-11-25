const encode = (text: string) => btoa(text);
const decode = (text: string) => atob(text);

export default {
    decode,
    encode,
};
