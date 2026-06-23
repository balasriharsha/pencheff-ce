export function generateStaticParams() {
  return [{ token: "_" }];
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
