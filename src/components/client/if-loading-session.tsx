"use client";

import { useSession } from "next-auth/react";
import React from "react";

interface Properties {
    children: React.ReactNode;
}

export default function IfLoadingSession(properties: Properties) {
    const { data: session } = useSession();

    return session === undefined ? properties.children : null;
}
