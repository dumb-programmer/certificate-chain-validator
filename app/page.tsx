"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import validateCertificate from "@/lib/actions";
import { domainFormSchema } from "@/lib/schema";
import { BadgeCheckIcon, LoaderCircleIcon } from "lucide-react";
import { useState } from "react";
import { CertificateInfo } from "@/lib/types";

export default function Home() {
  const form = useForm<z.infer<typeof domainFormSchema>>({
    defaultValues: {
      url: ""
    },
    resolver: zodResolver(domainFormSchema)
  });
  const [valid, setValid] = useState<boolean | null>(null);
  const [certificates, setCertificates] = useState<CertificateInfo[] | null>(null);

  const isSubmitting = form.formState.isSubmitting;

  const onSubmit = form.handleSubmit(async (data) => {
    if (!isSubmitting) {
      setValid(null);
      setCertificates(null);
      const response = await validateCertificate(data);
      if (response.certificates) {
        setValid(response.valid);
        setCertificates(response.certificates);
      }
    }
  });


  return (
    <main className="flex justify-center items-center min-h-screen w-screen">
      <div>
        <Form {...form}>
          <form onSubmit={onSubmit} className="flex flex-col gap-8">
            <h1 className="scroll-m-20 text-4xl font-extrabold tracking-tight">
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
        {
          valid !== null &&
          <div className="mt-4 flex flex-col gap-2 justify-center items-center">
            <BadgeCheckIcon height={50} width={50} color="green" />
            <h2 className="scroll-m-20 text-xl font-semibold tracking-tight">Valid</h2>
          </div>
        }
        {
          certificates && certificates.map(cert => <div key={cert.serialNumber} className="mt-4 border p-4 rounded-md border-gray-300">
            <p>
              Serial ID: {cert.serialNumber}
            </p>
            <p>
              Subject: {cert.subjectInfo.map(info => `${info.value}, `)}
            </p>
            <p>
              Issuer: {cert.issuerInfo.map(info => `${info.value}, `)}
            </p>
          </div>
          )
        }
      </div>
    </main>
  );
}
