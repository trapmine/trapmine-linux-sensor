/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#include <syscall_defs.h>
#include <stdlib.h>
#include <check.h>
#include <message.c>
#include <message_ls.c>

#define SYSCALL_MESSAGE_CREATE_NAME(syscall) test_message_create_##syscall

#define SYSCALL_MESSAGE_CREATE_SUCCESS(syscall)                                \
	START_TEST(test_message_create_##syscall)                              \
	{                                                                      \
		struct message_state *ms;                                      \
		ms = allocate_message_struct(syscall, 0);                      \
		ck_assert_ptr_nonnull(ms);                                     \
		ms = free_message(ms);                                         \
		ck_assert_ptr_null(ms);                                        \
	}                                                                      \
	END_TEST

#define SYSCALL_MESSAGE_CREATE_FAIL(syscall)                                   \
	START_TEST(test_message_create_##syscall)                              \
	{                                                                      \
		struct message_state *ms;                                      \
		ms = allocate_message_struct(syscall, 0);                      \
		ck_assert_ptr_null(ms);                                        \
	}                                                                      \
	END_TEST

SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_EXECVE);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_MMAP);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_FORK);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_VFORK);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_CLONE);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_SOCKET);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_CONNECT);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_ACCEPT);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_PTRACE);
SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_FINIT_MODULE);
SYSCALL_MESSAGE_CREATE_SUCCESS(DUMP_MMAP_DATA);
SYSCALL_MESSAGE_CREATE_SUCCESS(LPE_COMMIT_CREDS);
SYSCALL_MESSAGE_CREATE_SUCCESS(MODPROBE_OVERWRITE);

// undefined
// SYSCALL_MESSAGE_CREATE_SUCCESS(SYS_MPROTECT);

#define INVALID_NEG -4
#define INVALID_SYS 500
#define INVALID_ZERO 0
SYSCALL_MESSAGE_CREATE_FAIL(INVALID_NEG);
SYSCALL_MESSAGE_CREATE_FAIL(INVALID_ZERO);
SYSCALL_MESSAGE_CREATE_FAIL(INVALID_SYS);

/* Message test cases */
START_TEST(test_message_allocate_data__SUCCESS)
{
	char data[8] = "Hello\0";
	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	allocate_message_data(&(MESSAGE_STRING(ms)), data, sizeof(data));
	ck_assert_ptr_nonnull(MESSAGE_STRING(ms));
	ck_assert_mem_eq(MESSAGE_STRING(ms), data, sizeof(data));
}
END_TEST

START_TEST(test_message_allocate_data__FAIL__copy_target_NULL)
{
	char data[8] = "Hello\0";

	void *target = allocate_message_data(NULL, data, sizeof(data));
	ck_assert_ptr_null(target);
}

START_TEST(test_message_allocate_data__FAIL__data_NULL)
{
	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	void *target = allocate_message_data(&(MESSAGE_STRING(ms)), NULL, 5);
	ck_assert_ptr_null(target);
}

START_TEST(test_message_allocate_data__FAIL__size_ltz)
{
	char data[8] = "Hello\0";
	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	void *target = allocate_message_data(&(MESSAGE_STRING(ms)), data, 0);
	ck_assert_ptr_null(target);
}

START_TEST(test_legal_event__SUCCESS)
{
	struct probe_event_header eh;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	int res = is_legal_event(&eh);
	ck_assert(res != 0);
}

START_TEST(test_legal_event__FAIL)
{
	struct probe_event_header eh;

	memset(&eh, 0, sizeof(struct probe_event_header));
	int res = is_legal_event(&eh);
	ck_assert(res == 0);
}

START_TEST(test_get_event_header__SUCCESS__primary_data)
{
	struct probe_event_header eh;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	void *target = allocate_message_data(&(ms->primary_data), &eh,
					     sizeof(struct probe_event_header));
	ck_assert_ptr_nonnull(target);

	struct probe_event_header *res = get_event_header(ms);
	ck_assert_ptr_nonnull(res);

	int legal = is_legal_event(res);
	ck_assert(res != 0);
}

START_TEST(test_get_event_header__SUCCESS__string_data)
{
	struct probe_event_header eh;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	void *target = allocate_message_data(&(MESSAGE_STRING(ms)), &eh,
					     sizeof(struct probe_event_header));
	ck_assert_ptr_nonnull(target);

	struct probe_event_header *res = get_event_header(ms);
	ck_assert_ptr_nonnull(res);

	int legal = is_legal_event(res);
	ck_assert(res != 0);
}

START_TEST(test_get_event_header__SUCCESS__mmap_data)
{
	struct probe_event_header eh;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	void *target = allocate_message_data(&(MESSAGE_MMAP(ms)), &eh,
					     sizeof(struct probe_event_header));
	ck_assert_ptr_nonnull(target);

	struct probe_event_header *res = get_event_header(ms);
	ck_assert_ptr_nonnull(res);

	int legal = is_legal_event(res);
	ck_assert(res != 0);
}

START_TEST(test_get_event_header__FAIL__ms_NULL)
{
	struct probe_event_header *res = get_event_header(NULL);
	ck_assert_ptr_null(res);
}

START_TEST(test_get_event_header__FAIL__no_header)
{
	struct message_state *ms = allocate_message_struct(SYS_EXECVE, 0);
	ck_assert_ptr_nonnull(ms);

	struct probe_event_header *res = get_event_header(ms);
	ck_assert_ptr_null(res);
}

Suite *message_suite(void)
{
	Suite *s;
	TCase *tc_valid, *tc_invalid, *tc_alloc_data_S, *tc_alloc_data_F;
	TCase *tc_legal_event_S, *tc_legal_event_F, *tc_get_event_header_S,
		*tc_get_event_header_F;

	s = suite_create("Message");

	/* Valid input to allocate_message_struct */
	tc_valid = tcase_create("Create Valid");

	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_EXECVE));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_MMAP));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_FORK));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_VFORK));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_CLONE));
	//	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_MPROTECT));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_SOCKET));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_CONNECT));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_ACCEPT));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_PTRACE));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(SYS_FINIT_MODULE));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(DUMP_MMAP_DATA));
	tcase_add_test(tc_valid, SYSCALL_MESSAGE_CREATE_NAME(LPE_COMMIT_CREDS));
	tcase_add_test(tc_valid,
		       SYSCALL_MESSAGE_CREATE_NAME(MODPROBE_OVERWRITE));

	/* Invalid input to allocate_message_struct */
	tc_invalid = tcase_create("Create Invalid");
	tcase_add_test(tc_invalid, SYSCALL_MESSAGE_CREATE_NAME(INVALID_NEG));
	tcase_add_test(tc_invalid, SYSCALL_MESSAGE_CREATE_NAME(INVALID_SYS));
	tcase_add_test(tc_invalid, SYSCALL_MESSAGE_CREATE_NAME(INVALID_ZERO));

	/* Allocate data test case */
	tc_alloc_data_S = tcase_create("Allocate data success");
	tcase_add_test(tc_alloc_data_S, test_message_allocate_data__SUCCESS);

	tc_alloc_data_F = tcase_create("Allocate data fail");
	tcase_add_test(tc_alloc_data_F,
		       test_message_allocate_data__FAIL__copy_target_NULL);
	tcase_add_test(tc_alloc_data_F,
		       test_message_allocate_data__FAIL__data_NULL);
	tcase_add_test(tc_alloc_data_F,
		       test_message_allocate_data__FAIL__size_ltz);

	/* Legal event test case */
	tc_legal_event_S = tcase_create("Legal event");
	tcase_add_test(tc_legal_event_S, test_legal_event__SUCCESS);

	tc_legal_event_F = tcase_create("Illegal event");
	tcase_add_test(tc_legal_event_F, test_legal_event__FAIL);

	/* Get event header test case */
	tc_get_event_header_S = tcase_create("Get event header Success");
	tcase_add_test(tc_get_event_header_S,
		       test_get_event_header__SUCCESS__primary_data);
	tcase_add_test(tc_get_event_header_S,
		       test_get_event_header__SUCCESS__string_data);
	tcase_add_test(tc_get_event_header_S,
		       test_get_event_header__SUCCESS__mmap_data);

	tc_get_event_header_F = tcase_create("Get event header Fail");
	tcase_add_test(tc_get_event_header_F,
		       test_get_event_header__FAIL__ms_NULL);
	tcase_add_test(tc_get_event_header_F,
		       test_get_event_header__FAIL__no_header);

	suite_add_tcase(s, tc_valid);
	suite_add_tcase(s, tc_invalid);
	suite_add_tcase(s, tc_alloc_data_S);
	suite_add_tcase(s, tc_alloc_data_F);
	suite_add_tcase(s, tc_legal_event_S);
	suite_add_tcase(s, tc_legal_event_F);
	suite_add_tcase(s, tc_get_event_header_S);
	suite_add_tcase(s, tc_get_event_header_F);

	return s;
}

/* Message list test cases */

START_TEST(test_link_message__SUCCESS)
{
	struct message_state *ms;
	struct msg_list *head;
	struct probe_event_header eh;
	int curr;

	head = initialize_msg_list();
	ms = allocate_message_struct(SYS_EXECVE, 0);

	curr = head->elements;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	link_message(head, ms);
	ck_assert(head->first == ms);
	ck_assert_int_eq(head->elements, curr + 1);

	delete_message_list(head);
}
END_TEST

START_TEST(test_link_message__SUCCESS__multiple_add)
{
	struct message_state *ms1, *ms2, *ms3;
	struct msg_list *head;
	struct probe_event_header eh;
	int curr;

	head = initialize_msg_list();
	ms1 = allocate_message_struct(SYS_EXECVE, 0);
	ms2 = allocate_message_struct(SYS_SOCKET, 0);
	ms3 = allocate_message_struct(SYS_MMAP, 0);

	curr = head->elements;
	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	link_message(head, ms1);
	link_message(head, ms2);
	link_message(head, ms3);
	ck_assert_int_eq(head->elements, curr + 3);
	ck_assert(head->first == ms3);
	ck_assert(ms3->next_msg == ms2);
	ck_assert(ms2->next_msg == ms1);
	ck_assert(head->last == ms1);

	delete_message_list(head);
}
END_TEST

START_TEST(test_get_message_SUCCESS_notempty)
{
	struct message_state *ms, *orig;
	struct msg_list *head;
	struct probe_event_header eh;
	head = initialize_msg_list();

	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	orig = allocate_message_struct(SYS_EXECVE, 0);
	allocate_message_data(&(orig->primary_data), &eh,
			      sizeof(struct probe_event_header));
	link_message(head, orig);

	ms = get_message(head, &eh, 0);
	ck_assert(ms == orig);
	ck_assert(EVENT_HEADER_EQ(&eh, ms->primary_data) == 1);

	head = delete_message_list(head);
}
END_TEST

START_TEST(test_get_message_SUCCESS_empty)
{
	struct message_state *ms;
	struct msg_list *head;
	struct probe_event_header eh;

	head = initialize_msg_list();

	eh.data_type = Primary_Data;
	eh.syscall_nr = SYS_EXECVE;
	eh.event_time = 10000;
	eh.tgid_pid = (1UL << 32) | 1;

	ms = get_message(head, &eh, 0);
	ck_assert_ptr_nonnull(ms);
	ck_assert_ptr_null(ms->primary_data);
	ck_assert_ptr_null(MESSAGE_STRING(ms));
	ck_assert_ptr_null(MESSAGE_MMAP(ms));

	head = delete_message_list(head);
}
END_TEST

START_TEST(test_unlink__SUCCESS__one_msg)
{
	struct message_state *ms;
	struct msg_list *head;

	head = initialize_msg_list();

	ms = allocate_message_struct(SYS_EXECVE, 0);
	link_message(head, ms);
	int curr = head->elements;

	unlink_message(head, ms);
	ck_assert(head->elements == (curr - 1));
	ck_assert_ptr_null(head->first);
	ck_assert_ptr_null(head->last);

	head = delete_message_list(head);
}
END_TEST

int not_in_list(struct msg_list *head, struct message_state *ms)
{
	struct message_state *tmp;

	tmp = head->first;
	while (tmp != NULL) {
		if (tmp == ms)
			return 0;

		tmp = tmp->next_msg;
	}

	return 1;
}

START_TEST(test_unlink__SUCCESS__multiple_msgs)
{
	struct message_state *ms1, *ms2, *ms3;
	struct msg_list *head;

	head = initialize_msg_list();

	ms1 = allocate_message_struct(SYS_EXECVE, 0);
	ms2 = allocate_message_struct(SYS_EXECVE, 0);
	ms3 = allocate_message_struct(SYS_EXECVE, 0);
	link_message(head, ms1);
	link_message(head, ms2);
	link_message(head, ms3);

	int curr = head->elements;

	unlink_message(head, ms1);
	ck_assert(not_in_list(head, ms1) == 1);
	ck_assert(head->elements == (curr - 1));
	curr = head->elements;

	unlink_message(head, ms2);
	ck_assert(not_in_list(head, ms2) == 1);
	ck_assert(head->elements == (curr - 1));
	curr = head->elements;

	unlink_message(head, ms3);
	ck_assert(not_in_list(head, ms3) == 1);
	ck_assert(head->elements == (curr - 1));
	curr = head->elements;

	ck_assert(head->elements == 0);

	free_message(ms1);
	free_message(ms2);
	free_message(ms3);

	head = delete_message_list(head);
}
END_TEST

START_TEST(test_unlink__SUCCESS__empty_list)
{
	struct msg_list *head;
	struct message_state *ms;

	ms = allocate_message_struct(SYS_EXECVE, 0);
	head = initialize_msg_list();

	unlink_message(head, ms);

	free_message(ms);
	delete_message_list(head);
}
END_TEST

START_TEST(test_delete_message__SUCCESS)
{
	struct msg_list *head;
	struct message_state *ms;

	head = initialize_msg_list();
	ms = allocate_message_struct(SYS_EXECVE, 0);

	link_message(head, ms);

	remove_message_from_list(head, &ms);
	ck_assert_ptr_null(ms);
	ck_assert(head->elements == 0);

	head = delete_message_list(head);
}
END_TEST

START_TEST(test_transition_message_complete_SUCCESS)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) == 1);
}
END_TEST

START_TEST(test_transition_message_complete_FAIL_with_CODE_FAILED)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_FAILED);
	ck_assert(IS_MS_COMPLETE(ms) == 0);
}
END_TEST

START_TEST(test_transition_message_complete_FAIL_with_CODE_RETRY)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_FAILED);
	ck_assert(IS_MS_COMPLETE(ms) == 0);
}
END_TEST

START_TEST(test_transition_db_saved_SUCCESS)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert_msg(IS_MS_COMPLETE(ms) != 0, "ms->progress != complete");

	transition_ms_progress(ms, MS_DB_SAVED, CODE_SUCCESS);
	ck_assert_msg(IS_MS_DB_SAVED(ms) != 0, "ms->progress != db_saved");
}
END_TEST

START_TEST(test_transition_db_saved_CODE_FAILED_to_gc)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_DB_SAVED, CODE_FAILED);
	ck_assert_msg(IS_MS_DB_SAVED(ms) == 0, "ms->progress == db_saved");
	ck_assert_msg(IS_MS_GC(ms) != 0, "ms->progress != gc");
}
END_TEST

START_TEST(test_transition_db_saved_CODE_RETRY_no_transition_to_gc)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_DB_SAVED, CODE_RETRY);
	ck_assert(IS_MS_DB_SAVED(ms) == 0);
	ck_assert(IS_MS_GC(ms) == 0);
}
END_TEST

START_TEST(test_transition_context_CODE_SUCCES)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_SUCCESS);
	ck_assert_msg(IS_MS_CTX_SAVED(ms) != 0, "ms->progress != ctx_saved");

	ck_assert_msg(IS_MS_GC(ms) == 0, "ms->progress == gc");
}

START_TEST(test_transition_context_CODE_RETRY)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_RETRY);
	ck_assert_msg(IS_MS_CTX_SAVED(ms) == 0, "ms->progress != ctx_saved");

	ck_assert_msg(IS_MS_GC(ms) == 0, "ms->progress == gc");
}

START_TEST(test_transition_context_CODE_FAILED_transition_to_ignored)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_FAILED);
	ck_assert_msg(IS_MS_CTX_SAVED(ms) == 0, "ms->progress != ctx_saved");
	ck_assert_msg(IS_MS_IGNORE_CTX_SAVE(ms) == 1,
		      "ms->progress != ignore_ctx");

	ck_assert_msg(IS_MS_GC(ms) == 0, "ms->progress == gc");
}

START_TEST(test_transition_end_state_COMPLETE)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	ck_assert(IS_MS_GC(ms) == 0);
}

START_TEST(test_transition_end_state_MS_DB_SAVED_not_set)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_SUCCESS);
	ck_assert(IS_MS_GC(ms) == 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_FAILED);
	ck_assert(IS_MS_GC(ms) == 0);
}

START_TEST(test_transition_end_state_MS_DB_SAVED_set_CTX_SAVED_set)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_DB_SAVED, CODE_SUCCESS);
	ck_assert(IS_MS_DB_SAVED(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_SUCCESS);
	ck_assert(IS_MS_CTX_SAVED(ms) != 0);

	ck_assert(IS_MS_GC(ms) == 1);
}

START_TEST(test_transition_end_state_MS_DB_SAVED_set_CTX_IGNORE_set)
{
	struct message_state *ms;
	ms = allocate_message_struct(SYS_EXECVE, 0);

	ck_assert(ms->progress == 0);
	transition_ms_progress(ms, MS_COMPLETE, CODE_SUCCESS);
	ck_assert(IS_MS_COMPLETE(ms) != 0);

	transition_ms_progress(ms, MS_DB_SAVED, CODE_SUCCESS);
	ck_assert(IS_MS_DB_SAVED(ms) != 0);

	transition_ms_progress(ms, MS_CTX_SAVED, CODE_FAILED);
	ck_assert(IS_MS_CTX_SAVED(ms) == 0);
	ck_assert(IS_MS_IGNORE_CTX_SAVE(ms) != 0);

	ck_assert(IS_MS_GC(ms) == 1);
}

Suite *message_list_suite(void)
{
	Suite *s;
	TCase *tc_link_S, *tc_get_message_S;
	TCase *tc_unlink_S, *tc_delete_message_S;
	TCase *tc_transition_message;

	s = suite_create("Message List");

	/* Link messages */
	tc_link_S = tcase_create("Link Messages success");
	tcase_add_test(tc_link_S, test_link_message__SUCCESS);
	tcase_add_test(tc_link_S, test_link_message__SUCCESS__multiple_add);

	/* Get message */
	tc_get_message_S = tcase_create("Get message success");
	tcase_add_test(tc_get_message_S, test_get_message_SUCCESS_empty);
	tcase_add_test(tc_get_message_S, test_get_message_SUCCESS_notempty);

	/* Unlink message */
	tc_unlink_S = tcase_create("Unlink success");
	tcase_add_test(tc_unlink_S, test_unlink__SUCCESS__one_msg);
	tcase_add_test(tc_unlink_S, test_unlink__SUCCESS__multiple_msgs);
	tcase_add_test(tc_unlink_S, test_unlink__SUCCESS__empty_list);

	/* Delete message */
	tc_delete_message_S = tcase_create("Delete message success");
	tcase_add_test(tc_delete_message_S, test_delete_message__SUCCESS);

	/* Transition message */
	tc_transition_message = tcase_create("Transtion message");
	tcase_add_test(tc_transition_message,
		       test_transition_message_complete_SUCCESS);
	tcase_add_test(tc_transition_message,
		       test_transition_message_complete_FAIL_with_CODE_FAILED);
	tcase_add_test(tc_transition_message,
		       test_transition_message_complete_FAIL_with_CODE_RETRY);
	tcase_add_test(tc_transition_message, test_transition_db_saved_SUCCESS);
	tcase_add_test(tc_transition_message,
		       test_transition_db_saved_CODE_FAILED_to_gc);
	tcase_add_test(tc_transition_message,
		       test_transition_db_saved_CODE_RETRY_no_transition_to_gc);
	tcase_add_test(tc_transition_message,
		       test_transition_context_CODE_SUCCES);
	tcase_add_test(tc_transition_message,
		       test_transition_context_CODE_SUCCES);
	tcase_add_test(
		tc_transition_message,
		test_transition_context_CODE_FAILED_transition_to_ignored);
	tcase_add_test(tc_transition_message,
		       test_transition_end_state_COMPLETE);
	tcase_add_test(tc_transition_message,
		       test_transition_end_state_MS_DB_SAVED_not_set);
	tcase_add_test(tc_transition_message,
		       test_transition_end_state_MS_DB_SAVED_set_CTX_SAVED_set);
	tcase_add_test(
		tc_transition_message,
		test_transition_end_state_MS_DB_SAVED_set_CTX_IGNORE_set);

	suite_add_tcase(s, tc_link_S);
	suite_add_tcase(s, tc_get_message_S);
	suite_add_tcase(s, tc_unlink_S);
	suite_add_tcase(s, tc_delete_message_S);
	suite_add_tcase(s, tc_transition_message);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s1;
	SRunner *sr;

	s1 = message_suite();
	sr = srunner_create(s1);
	srunner_add_suite(sr, message_list_suite());

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
