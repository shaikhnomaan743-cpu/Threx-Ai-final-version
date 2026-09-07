import { forwardRef, useMemo, useState } from "react";
import { cn } from "../../lib/utils";
import { ChevronUp, ChevronDown, Search, Filter, MoreHorizontal } from "lucide-react";

export interface Column<T> {
  key: keyof T | string;
  header: string;
  render?: (value: any, row: T, index: number) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  align?: "left" | "center" | "right";
  className?: string;
}

export interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  keyExtractor: (row: T) => string;
  onRowClick?: (row: T) => void;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
  onSort?: (key: string, order: "asc" | "desc") => void;
  filterable?: boolean;
  filterPlaceholder?: string;
  onFilter?: (value: string) => void;
  loading?: boolean;
  emptyMessage?: string;
  rowClassName?: (row: T) => string;
  selectedKeys?: Set<string>;
  onSelectionChange?: (keys: Set<string>) => void;
  actions?: (row: T) => React.ReactNode;
  stickyHeader?: boolean;
  className?: string;
}

function SortIcon({ order }: { order: "asc" | "desc" }) {
  return order === "asc" ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />;
}

export function DataTable<T>({
  data,
  columns,
  keyExtractor,
  onRowClick,
  sortBy,
  sortOrder,
  onSort,
  filterable = false,
  filterPlaceholder = "Filter...",
  onFilter,
  loading = false,
  emptyMessage = "No data available",
  rowClassName,
  selectedKeys,
  onSelectionChange,
  actions,
  stickyHeader = true,
  className,
}: DataTableProps<T>) {
  const [filterValue, setFilterValue] = useState("");
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);

  const handleFilterChange = (value: string) => {
    setFilterValue(value);
    onFilter?.(value);
  };

  const filteredData = useMemo(() => {
    if (!filterValue) return data;
    const lower = filterValue.toLowerCase();
    return data.filter(row => 
      columns.some(col => {
        const value = row[col.key as keyof T];
        return String(value).toLowerCase().includes(lower);
      })
    );
  }, [data, filterValue, columns]);

  const sortedData = useMemo(() => {
    if (!sortBy || !onSort) return filteredData;
    return [...filteredData].sort((a, b) => {
      const aVal = a[sortBy as keyof T];
      const bVal = b[sortBy as keyof T];
      if (aVal === bVal) return 0;
      const comparison = aVal < bVal ? -1 : 1;
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [filteredData, sortBy, sortOrder, onSort]);

  const handleSort = (key: string) => {
    const column = columns.find(c => c.key === key);
    if (!column?.sortable) return;
    
    if (sortBy === key) {
      onSort(key, sortOrder === "asc" ? "desc" : "asc");
    } else {
      onSort(key, "asc");
    }
  };

  const handleRowClick = (row: T, e: React.MouseEvent) => {
    if (actions && e.currentTarget.contains(e.target as Node)) return;
    onRowClick?.(row);
  };

  const isSelected = (row: T) => selectedKeys?.has(keyExtractor(row)) || false;

  return (
    <div className={cn("w-full", className)}>
      {filterable && (
        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--color-text-muted)]" aria-hidden="true" />
          <input
            type="text"
            placeholder={filterPlaceholder}
            value={filterValue}
            onChange={(e) => handleFilterChange(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] rounded-[6px] text-sm transition-all duration-150 focus:outline-none focus:border-[var(--color-accent-cyan)] focus:ring-1 focus:ring-[var(--color-accent-cyan)]"
            aria-label={filterPlaceholder}
          />
        </div>
      )}

      <div className="table-container">
        <table className="table" role="grid">
          <thead>
            <tr className={cn(stickyHeader && "sticky top-0 z-10")}>
              {columns.map((column) => (
                <th
                  key={String(column.key)}
                  style={{ width: column.width, textAlign: column.align }}
                  className={cn(
                    column.sortable && "cursor-pointer select-none hover:bg-[var(--color-border-card)]/50",
                    column.className
                  )}
                  onClick={() => handleSort(String(column.key))}
                  aria-sort={sortBy === String(column.key) ? (sortOrder === "asc" ? "ascending" : "descending") : "none"}
                >
                  <div className="flex items-center gap-1.5">
                    <span>{column.header}</span>
                    {column.sortable && sortBy === column.key && <SortIcon order={sortOrder} />}
                  </div>
                </th>
              ))}
              {actions && <th className="w-12 text-right" />}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={columns.length + (actions ? 1 : 0)} className="text-center py-12 text-[var(--color-text-muted)]">
                  <div className="flex items-center justify-center gap-2">
                    <svg className="animate-spin w-5 h-5 text-[var(--color-accent-cyan)]" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Loading...
                  </div>
                </td>
              </tr>
            ) : sortedData.length === 0 ? (
              <tr>
                <td colSpan={columns.length + (actions ? 1 : 0)} className="text-center py-12 text-[var(--color-text-muted)]">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              sortedData.map((row, rowIndex) => {
                const key = keyExtractor(row);
                const selected = isSelected(row);
                
                return (
                  <tr
                    key={key}
                    onClick={(e) => handleRowClick(row, e)}
                    onMouseEnter={() => setHoveredKey(key)}
                    onMouseLeave={() => setHoveredKey(null)}
                    className={cn(
                      rowClassName?.(row),
                      selected && "bg-[var(--color-accent-cyan-dim)] border-l-2 border-[var(--color-accent-cyan)]",
                      hoveredKey === key && "bg-[var(--color-bg-elevated-2)]/50"
                    )}
                    style={{ cursor: onRowClick ? "pointer" : "default" }}
                    tabIndex={onRowClick ? 0 : undefined}
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onRowClick?.(row); }}
                  >
                    {columns.map((column) => (
                      <td
                        key={String(column.key)}
                        style={{ textAlign: column.align }}
                        className={cn(
                          "font-mono tabular-nums",
                          column.key === "sourceIp" || column.key === "destinationIp" || column.key === "destination" 
                            ? "font-mono" 
                            : "",
                          column.className
                        )}
                      >
                        {column.render 
                          ? column.render(row[column.key as keyof T] as any, row, rowIndex)
                          : String(row[column.key as keyof T] ?? "—")}
                      </td>
                    ))}
                    {actions && (
                      <td className="text-right pr-4">
                        {actions(row)}
                      </td>
                    )}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-[var(--color-text-muted)]">
        <span>Showing {sortedData.length} of {data.length} rows</span>
        {filterValue && (
          <button
            onClick={() => handleFilterChange("")}
            className="text-[var(--color-accent-cyan)] hover:underline text-sm"
          >
            Clear filter
          </button>
        )}
      </div>
    </div>
  );
}

DataTable.displayName = "DataTable";