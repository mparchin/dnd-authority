using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace authority.Migrations
{
    /// <inheritdoc />
    public partial class ResetPasswordTokenMigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ResetExpirationTime",
                table: "Users",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "ResetToken",
                table: "Users",
                type: "text",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ResetExpirationTime",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ResetToken",
                table: "Users");
        }
    }
}
