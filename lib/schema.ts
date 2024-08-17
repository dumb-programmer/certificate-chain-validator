import { z } from "zod";

export const domainFormSchema = z.object({
  url: z.string().url()
});