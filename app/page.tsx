import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function Home() {
  return (
    <main className="flex justify-center items-center min-h-screen w-screen">
      <div>
        <form className="flex flex-col gap-8">
          <h1 className="scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl">
            Certificate Chain Validator
          </h1>
          <Input placeholder="https://test.org" />
          <Button >
            Validate
          </Button>
        </form>
      </div>
    </main>
  );
}
