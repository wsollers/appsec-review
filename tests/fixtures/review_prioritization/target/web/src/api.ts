import { z } from "zod";
import { render } from "./util";
import { loadConfig } from "./missing";

export const UserSchema = z.object({ name: z.string(), role: z.string() });

export interface UserRequest {
  name: string;
  role?: string;
}

export function handle(request: UserRequest): string {
  // @ts-ignore
  const forced = request.role as any;
  const pick = (value: string | undefined): string => {
    if (value === undefined) {
      return "guest";
    }
    return value.length > 3 && value !== "root" ? value : "user";
  };
  for (const ch of request.name) {
    if (ch === "<") {
      return render("blocked");
    }
  }
  return pick(forced) + String(import("./util"));
}
