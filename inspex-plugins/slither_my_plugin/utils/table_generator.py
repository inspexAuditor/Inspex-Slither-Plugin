def markdownTableFromSlitherResult(table, cml, sortBy=None):
    # print("# Summary Table of " + detector.ARGUMENT + "\n")
    # print("## Target:")
    res = ""
    if len(table) <= 1:
        return res
    if sortBy is not None:
        fTarget = table[0].index(sortBy)
        if sortBy == "File":
            try:
                table = [table[0]] + sorted(table[1:], key=lambda x:(x[fTarget].split(" ")[0], int(x[fTarget].split("(L:")[1][:-1])))
            except:
                table = [table[0]] + sorted(table[1:], key=lambda x:x[fTarget])
        else:
            table = [table[0]] + sorted(table[1:], key=lambda x:x[fTarget])
    for i, r in enumerate(table):
        res += "|" + "|".join([(" %-"+str(cml[j])+"s ") % c for j,c in enumerate(r)]) + "|" + "\n"
        if i==0:
            res +=  "|" + "".join([ "-"*(c+2)+"|" for c in cml]) + "\n"
    res += "\n"
    return res