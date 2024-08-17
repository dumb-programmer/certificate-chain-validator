"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import validateCertificate from "@/lib/actions";
import { domainFormSchema } from "@/lib/schema";
import { LoaderCircle, LoaderCircleIcon } from "lucide-react";

export default function Home() {
  const form = useForm<z.infer<typeof domainFormSchema>>({
    defaultValues: {
      url: ""
    },
    resolver: zodResolver(domainFormSchema)
  });

  const onSubmit = form.handleSubmit(async (data) => {
    console.log(data);
    await validateCertificate(data);
  });

  const isSubmitting = form.formState.isSubmitting;

  return (
    <main className="flex justify-center items-center min-h-screen w-screen">
      <div>
        <Form {...form}>
          <form onSubmit={onSubmit} className="flex flex-col gap-8">
            <h1 className="scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl">
              Certificate Chain Validator
            </h1>
            <FormField
              control={form.control}
              name="url"
              render={({ field }) => (
                <FormItem>
                  <FormControl>
                    <Input placeholder="https://test.org" type="url" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit">{isSubmitting ? <LoaderCircleIcon className="animate-spin" /> : "Validate"}</Button>
          </form>
        </Form>
      </div>
    </main>
  );
}
