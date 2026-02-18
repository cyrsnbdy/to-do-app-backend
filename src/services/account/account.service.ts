import Account from "@/models/account/account.model";
import {
  AccountDocumentType,
  AccountFilterType,
  AccountType,
  SessionType,
} from "@/types/account/account.type";

export const findAccountS = async (
  filter: AccountFilterType,
  selectFields?: string,
): Promise<AccountDocumentType | null> => {
  const account = await Account.findOne(filter)
    .select(selectFields || "")
    .exec();
  return account as AccountDocumentType | null;
};

export const pushSessionS = async (accountId: string, session: SessionType) => {
  return Account.findByIdAndUpdate(
    accountId,
    { $push: { sessions: session } },
    { new: true },
  );
};

export const registerS = async (data: Partial<AccountType>) => {
  const account = await Account.create(data);
  return account;
};
