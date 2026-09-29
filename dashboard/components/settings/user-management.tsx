"use client"

import { useState, useEffect } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { MoreHorizontal, UserPlus, Edit, Trash2 } from "lucide-react"
import { useAppDispatch, useUsers, useUsersLoading } from "@/lib/store/hooks"
import { fetchUsersRequest, deleteUserRequest } from "@/lib/store/slices/usersSlice"
import type { User } from "@/lib/store/types"
import { UserEditDialog } from "./user-edit-dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"

interface UserManagementProps {
  isAdmin: boolean
}

export function UserManagement({ isAdmin }: UserManagementProps) {
  const dispatch = useAppDispatch()
  const users = useUsers()
  const loading = useUsersLoading()
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)

  useEffect(() => {
    dispatch(fetchUsersRequest())
  }, [dispatch])

  const handleAddUser = () => {
    setSelectedUser(null)
    setIsEditDialogOpen(true)
  }

  const handleEditUser = (user: User) => {
    setSelectedUser(user)
    setIsEditDialogOpen(true)
  }

  const handleDeleteUser = (user: User) => {
    setSelectedUser(user)
    setIsDeleteDialogOpen(true)
  }

  const confirmDelete = () => {
    if (selectedUser) {
      dispatch(deleteUserRequest(selectedUser.id))
      setIsDeleteDialogOpen(false)
      setSelectedUser(null)
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base sm:text-lg font-medium text-[#EDEDED]">User Accounts</h3>
          <p className="text-sm text-[#9A9A9A] mt-1">Manage user access and roles.</p>
        </div>
        <Button
          onClick={handleAddUser}
          disabled={!isAdmin || loading}
          className="bg-[#FF6B00] hover:bg-[#E55A00] text-black disabled:opacity-50 disabled:cursor-not-allowed h-10 px-4 touch-manipulation w-full sm:w-auto"
        >
          <UserPlus className="mr-2 h-4 w-4" />
          Add User
        </Button>
      </div>

      {/* Table Container */}
      <div className="border border-[#2A2A2A] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b-[#2A2A2A]">
                <TableHead className="text-[#9A9A9A] text-xs sm:text-sm">Name</TableHead>
                <TableHead className="text-[#9A9A9A] hidden sm:table-cell text-xs sm:text-sm">Email</TableHead>
                <TableHead className="text-[#9A9A9A] text-xs sm:text-sm">Role</TableHead>
                <TableHead className="text-[#9A9A9A] hidden md:table-cell text-xs sm:text-sm">Created At</TableHead>
                <TableHead className="w-[50px]">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id} className="border-b-[#2A2A2A] hover:bg-[#1F1F1F]">
                  <TableCell className="font-medium text-[#EDEDED] py-3 sm:py-4">
                    <div>
                      <div className="font-medium text-sm sm:text-base">{user.name}</div>
                      <div className="text-xs text-[#9A9A9A] sm:hidden mt-1">{user.email}</div>
                    </div>
                  </TableCell>
                  <TableCell className="text-[#9A9A9A] hidden sm:table-cell text-sm">{user.email}</TableCell>
                  <TableCell className="py-3 sm:py-4">
                    <span
                      className={`px-2 py-1 text-xs rounded-full ${
                        user.role === "admin" ? "bg-[#FF6B00]/20 text-[#FF6B00]" : "bg-gray-600/20 text-gray-300"
                      }`}
                    >
                      {user.role}
                    </span>
                  </TableCell>
                  <TableCell className="text-[#9A9A9A] hidden md:table-cell text-sm">
                    {new Date(user.createdAt).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="py-3 sm:py-4">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          className="h-8 w-8 p-0 touch-manipulation"
                          disabled={!isAdmin || loading}
                        >
                          <span className="sr-only">Open menu</span>
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED]">
                        <DropdownMenuItem
                          onClick={() => handleEditUser(user)}
                          className="cursor-pointer hover:!bg-[#2A2A2A] py-2.5 px-3 touch-manipulation"
                        >
                          <Edit className="mr-2 h-4 w-4" /> Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleDeleteUser(user)}
                          className="cursor-pointer text-red-400 hover:!bg-red-600/20 hover:!text-red-300 py-2.5 px-3 touch-manipulation"
                        >
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>

      <UserEditDialog isOpen={isEditDialogOpen} setIsOpen={setIsEditDialogOpen} user={selectedUser} />

      <AlertDialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <AlertDialogContent className="bg-[#1B1B1B] border-[#2A2A2A] text-[#EDEDED] mx-4 sm:mx-0 max-w-md sm:max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-base sm:text-lg">Are you sure?</AlertDialogTitle>
            <AlertDialogDescription className="text-[#9A9A9A] text-sm">
              This action cannot be undone. This will permanently delete the user account for {selectedUser?.name}.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="flex-col sm:flex-row gap-2 sm:gap-0">
            <AlertDialogCancel className="bg-transparent border-[#2A2A2A] hover:bg-[#2A2A2A] h-10 touch-manipulation w-full sm:w-auto">
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 text-white h-10 touch-manipulation w-full sm:w-auto"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
