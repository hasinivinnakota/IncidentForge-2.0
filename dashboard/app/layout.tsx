import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import { ReduxProvider } from "@/components/providers/redux-provider"
import "./globals.css"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "IncidentForge | Security Operations Center",
  description: "AI-assisted SOC investigation and incident response platform",
  generator: "v0.dev",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="bg-[#050505]">
      <body className={inter.className}>
        <ReduxProvider>{children}</ReduxProvider>
      </body>
    </html>
  )
}
