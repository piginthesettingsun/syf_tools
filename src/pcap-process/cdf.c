#include <stdio.h>
#include <string.h>
#include <stdint.h>

const int max_num = 1000000;

/*----------------------------------------------------------------------------*/
static inline void get_mid(uint64_t a[], int l, int r)
{
	int m = (l + r)/2;
	int i;

	if (a[l] < a[m]) {
		// l<m
		if (a[m] < a[r]) {
			// l<m<r
			i = m;
		} else {
			// r<m
			if (a[l] < a[r]) {
				// l<r<m
				i = r;
			} else {
				// r<l<m
				i = l;
			}
		}
	} else {
		// m<l
		if (a[r] < a[m]) {
			// r<m<l
			i = m;
		} else {
			// m<r
			if (a[r] < a[l]) {
				// m<r<l
				i = r;
			} else {
				// m<l<r
				i = l;
			}
		}
	}
	if (i == l ) {
		return;
	}
	uint64_t temp = a[i];
	a[i] = a[l];
	a[l] = temp;
}

static void sort(uint64_t a[], int left, int right)
{
	if (left >= right) {
		return;
	}

	int i = left;
	int j = right;
	get_mid(a, left, right);
	uint64_t key = a[left];	// make a hole at left
	
	while (i < j) {
		while (i<j&&a[j]>key) {
			j--;
		}
		if (i < j) {
			a[i++] = a[j];
		}
		while (i < j&&a[i] < key) {
			i++;
		}
		if (i < j) {
			a[j--] = a[i];
		}
	}
	a[i] = key; // i==j, pointing to the hole

	sort(a, left, i - 1);
	sort(a, i + 1, right);
}
/*----------------------------------------------------------------------------*/
static uint64_t scan_data(const char* file_in, uint64_t *data)
{
	FILE *fp = fopen(file_in, "r");
	uint64_t count = 0;

	while (!feof(fp)) {
		fscanf(fp, "%llu\n", &data[count++]);
	}

	close(fp);
	return count;
}

static inline int
print_sorted_result(uint64_t count, uint64_t *data)
{
	int num = 13;
	int i, index;
	double proportions[] = {0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.99, 0.999, 1};
	sort(data, 0, count-1);
	fprintf(stderr, "result from %d requests:\n"
			"proportion\t delay\n");
	for (i=0; i<num; i++) {
		index = (uint64_t)(proportions[i] * (count-1));
		fprintf(stderr, "%lf\t\t %llu\n", proportions[i], data[index]);
	}
	for (i=0; i<count; i++) {
		fprintf(stdout, "%llu\n", data[i]);
	}
}
/*----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	uint64_t *data = calloc(max_num, sizeof(uint64_t));
	
	uint64_t num = scan_data(argv[1], data);
	if (num > max_num) {
		printf("too much data!\n");
		exit(-1);
	}
	print_sorted_result(num, data);
	return 1;
}
