namespace Tolap.Store;

/// <summary>
/// Resolves group and role memberships for a user.
/// </summary>
public interface IIdentityResolver
{
    /// <summary>
    /// Returns the group identifiers the user belongs to.
    /// </summary>
    Task<string[]> GetGroupsForUserAsync(string userId);

    /// <summary>
    /// Returns the role identifiers assigned to the user.
    /// </summary>
    Task<string[]> GetRolesForUserAsync(string userId);
}
