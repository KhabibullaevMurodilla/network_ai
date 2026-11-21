"use client";
import { createContext, useContext } from "react";
import type { Focus } from "./focus";

export type Profile = { role: string; focus: Focus | null; userId: string; tenantName: string; reload: () => void };

export const ProfileContext = createContext<Profile | null>(null);
export const useProfile = () => useContext(ProfileContext);
